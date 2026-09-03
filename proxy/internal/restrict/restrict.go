// Package restrict provides connection-level access control based on
// IP CIDR ranges and geolocation (country codes).
package restrict

import (
	"net/netip"
	"slices"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/proxy/internal/geolocation"
)

// defaultLogger is used when no logger is provided to ParseFilter.
var defaultLogger = log.NewEntry(log.StandardLogger())

// GeoResolver resolves an IP address to geographic information.
type GeoResolver interface {
	LookupAddr(addr netip.Addr) geolocation.Result
	Available() bool
}

// DecisionType is the type of CrowdSec remediation action.
type DecisionType string

const (
	DecisionBan      DecisionType = "ban"
	DecisionCaptcha  DecisionType = "captcha"
	DecisionThrottle DecisionType = "throttle"
)

// CrowdSecDecision holds the type of a CrowdSec decision.
type CrowdSecDecision struct {
	Type DecisionType
}

// CrowdSecChecker queries CrowdSec decisions for an IP address.
type CrowdSecChecker interface {
	CheckIP(addr netip.Addr) *CrowdSecDecision
	Ready() bool
}

// CrowdSecMode is the per-service enforcement mode.
type CrowdSecMode string

const (
	CrowdSecOff     CrowdSecMode = ""
	CrowdSecEnforce CrowdSecMode = "enforce"
	CrowdSecObserve CrowdSecMode = "observe"
)

// AllowMatch controls how the configured allowlists (CIDR, country) combine.
// Blocklists are always a separate hard-deny gate and are unaffected by it.
type AllowMatch string

const (
	// AllowMatchAll requires the address to match every configured allowlist
	// (AND). This is the default and preserves the historical behavior.
	AllowMatchAll AllowMatch = "all"
	// AllowMatchAny requires the address to match at least one configured
	// allowlist (OR), e.g. "allowed country OR allowed CIDR".
	AllowMatchAny AllowMatch = "any"
)

// normalizeAllowMatch maps unknown or empty values to the restrictive default
// (AllowMatchAll) so an unrecognized mode never loosens access.
func normalizeAllowMatch(m AllowMatch) AllowMatch {
	if m == AllowMatchAny {
		return AllowMatchAny
	}
	return AllowMatchAll
}

// AppSecMode is the per-service CrowdSec AppSec (WAF) enforcement mode.
type AppSecMode string

const (
	// AppSecOff disables request inspection.
	AppSecOff AppSecMode = ""
	// AppSecEnforce blocks requests the engine flags, and fails closed when the
	// engine is unreachable.
	AppSecEnforce AppSecMode = "enforce"
	// AppSecObserve records the verdict without blocking.
	AppSecObserve AppSecMode = "observe"
)

// ParseAppSecMode maps a wire value to an AppSecMode. Unrecognized values map
// to AppSecOff so a typo never turns inspection into an unintended block.
func ParseAppSecMode(s string) AppSecMode {
	switch AppSecMode(s) {
	case AppSecEnforce:
		return AppSecEnforce
	case AppSecObserve:
		return AppSecObserve
	default:
		return AppSecOff
	}
}

// Enabled reports whether the mode asks for request inspection.
func (m AppSecMode) Enabled() bool {
	return m == AppSecEnforce || m == AppSecObserve
}

// Filter evaluates IP restrictions. CIDR checks are performed first
// (cheap), followed by country lookups (more expensive) only when needed.
type Filter struct {
	AllowedCIDRs     []netip.Prefix
	BlockedCIDRs     []netip.Prefix
	AllowedCountries []string
	BlockedCountries []string
	CrowdSec         CrowdSecChecker
	CrowdSecMode     CrowdSecMode
	// AllowMatch controls how the allowlists combine (AND vs OR). Empty means
	// AllowMatchAll.
	AllowMatch AllowMatch
}

// FilterConfig holds the raw configuration for building a Filter.
type FilterConfig struct {
	AllowedCIDRs     []string
	BlockedCIDRs     []string
	AllowedCountries []string
	BlockedCountries []string
	CrowdSec         CrowdSecChecker
	CrowdSecMode     CrowdSecMode
	AllowMatch       AllowMatch
	Logger           *log.Entry
}

// ParseFilter builds a Filter from the config. Returns nil if no restrictions
// are configured.
func ParseFilter(cfg FilterConfig) *Filter {
	hasCS := cfg.CrowdSecMode == CrowdSecEnforce || cfg.CrowdSecMode == CrowdSecObserve
	if len(cfg.AllowedCIDRs) == 0 && len(cfg.BlockedCIDRs) == 0 &&
		len(cfg.AllowedCountries) == 0 && len(cfg.BlockedCountries) == 0 && !hasCS {
		return nil
	}

	logger := cfg.Logger
	if logger == nil {
		logger = defaultLogger
	}

	f := &Filter{
		AllowedCountries: normalizeCountryCodes(cfg.AllowedCountries),
		BlockedCountries: normalizeCountryCodes(cfg.BlockedCountries),
		AllowMatch:       normalizeAllowMatch(cfg.AllowMatch),
	}
	if hasCS {
		f.CrowdSec = cfg.CrowdSec
		f.CrowdSecMode = cfg.CrowdSecMode
	}
	for _, cidr := range cfg.AllowedCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			logger.Warnf("skip invalid allowed CIDR %q: %v", cidr, err)
			continue
		}
		f.AllowedCIDRs = append(f.AllowedCIDRs, prefix.Masked())
	}
	for _, cidr := range cfg.BlockedCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			logger.Warnf("skip invalid blocked CIDR %q: %v", cidr, err)
			continue
		}
		f.BlockedCIDRs = append(f.BlockedCIDRs, prefix.Masked())
	}
	return f
}

func normalizeCountryCodes(codes []string) []string {
	if len(codes) == 0 {
		return nil
	}
	out := make([]string, len(codes))
	for i, c := range codes {
		out[i] = strings.ToUpper(c)
	}
	return out
}

// Verdict is the result of an access check.
type Verdict int

const (
	// Allow indicates the address passed all checks.
	Allow Verdict = iota
	// DenyCIDR indicates the address was blocked by a CIDR rule.
	DenyCIDR
	// DenyCountry indicates the address was blocked by a country rule.
	DenyCountry
	// DenyGeoUnavailable indicates that country restrictions are configured
	// but the geo lookup is unavailable.
	DenyGeoUnavailable
	// DenyCrowdSecBan indicates a CrowdSec "ban" decision.
	DenyCrowdSecBan
	// DenyCrowdSecCaptcha indicates a CrowdSec "captcha" decision.
	DenyCrowdSecCaptcha
	// DenyCrowdSecThrottle indicates a CrowdSec "throttle" decision.
	DenyCrowdSecThrottle
	// DenyCrowdSecUnavailable indicates enforce mode but the bouncer has not
	// completed its initial sync.
	DenyCrowdSecUnavailable
	// DenyAppSecBan indicates a CrowdSec AppSec "ban" remediation.
	DenyAppSecBan
	// DenyAppSecCaptcha indicates a CrowdSec AppSec "captcha" remediation.
	DenyAppSecCaptcha
	// DenyAppSecUnavailable indicates enforce mode but the AppSec engine could
	// not produce a verdict (unreachable, timed out, or it rejected the call).
	DenyAppSecUnavailable
)

// String returns the deny reason string matching the HTTP auth mechanism names.
func (v Verdict) String() string {
	switch v {
	case Allow:
		return "allow"
	case DenyCIDR:
		return "ip_restricted"
	case DenyCountry:
		return "country_restricted"
	case DenyGeoUnavailable:
		return "geo_unavailable"
	case DenyCrowdSecBan:
		return "crowdsec_ban"
	case DenyCrowdSecCaptcha:
		return "crowdsec_captcha"
	case DenyCrowdSecThrottle:
		return "crowdsec_throttle"
	case DenyCrowdSecUnavailable:
		return "crowdsec_unavailable"
	case DenyAppSecBan:
		return "appsec_ban"
	case DenyAppSecCaptcha:
		return "appsec_captcha"
	case DenyAppSecUnavailable:
		return "appsec_unavailable"
	default:
		return "unknown"
	}
}

// IsCrowdSec returns true when the verdict originates from a CrowdSec check.
func (v Verdict) IsCrowdSec() bool {
	switch v {
	case DenyCrowdSecBan, DenyCrowdSecCaptcha, DenyCrowdSecThrottle, DenyCrowdSecUnavailable:
		return true
	default:
		return false
	}
}

// IsAppSec returns true when the verdict originates from an AppSec inspection.
func (v Verdict) IsAppSec() bool {
	switch v {
	case DenyAppSecBan, DenyAppSecCaptcha, DenyAppSecUnavailable:
		return true
	default:
		return false
	}
}

// IsObserveOnly returns true when v is a CrowdSec verdict and the filter is in
// observe mode. Callers should log the verdict but not block the request.
func (f *Filter) IsObserveOnly(v Verdict) bool {
	if f == nil {
		return false
	}
	return v.IsCrowdSec() && f.CrowdSecMode == CrowdSecObserve
}

// CheckCIDR runs only the CIDR allow/block evaluation. Use this when
// country and CrowdSec checks don't apply — e.g. requests arriving
// from the WireGuard overlay, whose source addresses live in the
// CGNAT range and have no meaningful geolocation or IP-reputation
// data.
func (f *Filter) CheckCIDR(addr netip.Addr) Verdict {
	if f == nil {
		return Allow
	}
	return f.checkCIDR(addr.Unmap())
}

// Check evaluates whether addr is permitted. CIDR rules are evaluated
// first because they are O(n) prefix comparisons. Country rules run
// only when CIDR checks pass and require a geo lookup. CrowdSec checks
// run last.
func (f *Filter) Check(addr netip.Addr, geo GeoResolver) Verdict {
	if f == nil {
		return Allow
	}

	// Normalize v4-mapped-v6 (e.g. ::ffff:10.1.2.3) to plain v4 so that
	// IPv4 CIDR rules match regardless of how the address was received.
	addr = addr.Unmap()

	if f.AllowMatch == AllowMatchAny {
		return f.checkAny(addr, geo)
	}

	if v := f.checkCIDR(addr); v != Allow {
		return v
	}
	if v := f.checkCountry(addr, geo); v != Allow {
		return v
	}
	return f.checkCrowdSec(addr)
}

// checkAny evaluates the filter with OR semantics across allowlists: the
// address is admitted if it matches any configured allowlist (CIDR or country).
// Blocklists remain a hard-deny gate evaluated first and are independent of the
// allow-combine mode, so a blocklist match (or unverifiable country block) still
// denies. CrowdSec runs last, as in the default path.
//
// The country is resolved at most once and shared by both the blocklist and the
// allowlist, matching what the all-mode path does. Splitting the two checks into
// separate helpers cost a second geo lookup per connection whenever both country
// lists were configured.
func (f *Filter) checkAny(addr netip.Addr, geo GeoResolver) Verdict {
	for _, prefix := range f.BlockedCIDRs {
		if prefix.Contains(addr) {
			return DenyCIDR
		}
	}

	cidrActive := len(f.AllowedCIDRs) > 0
	cidrAllowed := false
	if cidrActive {
		for _, prefix := range f.AllowedCIDRs {
			if prefix.Contains(addr) {
				cidrAllowed = true
				break
			}
		}
	}

	countryActive := len(f.AllowedCountries) > 0
	// The blocklist is a hard gate, so it needs the country even when a CIDR
	// allowlist already admitted the address. The allowlist needs it only when
	// the CIDR list did not admit it, which is why a matching allowed CIDR
	// still skips the lookup when no country blocklist is configured.
	needCountry := len(f.BlockedCountries) > 0 || (countryActive && !cidrAllowed)

	country := ""
	if needCountry {
		if geo == nil || !geo.Available() {
			return DenyGeoUnavailable
		}
		country = geo.LookupAddr(addr).CountryCode
	}

	if country != "" && slices.Contains(f.BlockedCountries, country) {
		return DenyCountry
	}

	allowed := (!cidrActive && !countryActive) ||
		cidrAllowed ||
		(countryActive && country != "" && slices.Contains(f.AllowedCountries, country))
	if !allowed {
		// Both allowlists missing is reported against the CIDR list, the one
		// checked first, so the reason stays stable for existing access logs.
		if cidrActive {
			return DenyCIDR
		}
		return DenyCountry
	}

	return f.checkCrowdSec(addr)
}

func (f *Filter) checkCIDR(addr netip.Addr) Verdict {
	if len(f.AllowedCIDRs) > 0 {
		allowed := false
		for _, prefix := range f.AllowedCIDRs {
			if prefix.Contains(addr) {
				allowed = true
				break
			}
		}
		if !allowed {
			return DenyCIDR
		}
	}

	for _, prefix := range f.BlockedCIDRs {
		if prefix.Contains(addr) {
			return DenyCIDR
		}
	}
	return Allow
}

func (f *Filter) checkCountry(addr netip.Addr, geo GeoResolver) Verdict {
	if len(f.AllowedCountries) == 0 && len(f.BlockedCountries) == 0 {
		return Allow
	}

	if geo == nil || !geo.Available() {
		return DenyGeoUnavailable
	}

	result := geo.LookupAddr(addr)
	if result.CountryCode == "" {
		// Unknown country: deny if an allowlist is active, allow otherwise.
		// Blocklists are best-effort: unknown countries pass through since
		// the default policy is allow.
		if len(f.AllowedCountries) > 0 {
			return DenyCountry
		}
		return Allow
	}

	if len(f.AllowedCountries) > 0 {
		if !slices.Contains(f.AllowedCountries, result.CountryCode) {
			return DenyCountry
		}
	}

	if slices.Contains(f.BlockedCountries, result.CountryCode) {
		return DenyCountry
	}

	return Allow
}

func (f *Filter) checkCrowdSec(addr netip.Addr) Verdict {
	if f.CrowdSecMode == CrowdSecOff {
		return Allow
	}

	// Checker nil with enforce means CrowdSec was requested but the proxy
	// has no LAPI configured. Fail-closed.
	if f.CrowdSec == nil {
		if f.CrowdSecMode == CrowdSecEnforce {
			return DenyCrowdSecUnavailable
		}
		return Allow
	}

	if !f.CrowdSec.Ready() {
		if f.CrowdSecMode == CrowdSecEnforce {
			return DenyCrowdSecUnavailable
		}
		return Allow
	}

	d := f.CrowdSec.CheckIP(addr)
	if d == nil {
		return Allow
	}

	switch d.Type {
	case DecisionCaptcha:
		return DenyCrowdSecCaptcha
	case DecisionThrottle:
		return DenyCrowdSecThrottle
	default:
		return DenyCrowdSecBan
	}
}

// HasRestrictions returns true if any restriction rules are configured.
func (f *Filter) HasRestrictions() bool {
	if f == nil {
		return false
	}
	return len(f.AllowedCIDRs) > 0 || len(f.BlockedCIDRs) > 0 ||
		len(f.AllowedCountries) > 0 || len(f.BlockedCountries) > 0 ||
		f.CrowdSecMode == CrowdSecEnforce || f.CrowdSecMode == CrowdSecObserve
}
