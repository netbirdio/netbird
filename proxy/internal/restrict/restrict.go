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

// Filter evaluates IP restrictions. CIDR checks are performed first
// (cheap), followed by country lookups (more expensive) only when needed.
type Filter struct {
	AllowedCIDRs     []netip.Prefix
	BlockedCIDRs     []netip.Prefix
	AllowedCountries []string
	BlockedCountries []string
	CrowdSec         CrowdSecChecker
	CrowdSecMode     CrowdSecMode
}

// FilterConfig holds the raw configuration for building a Filter.
type FilterConfig struct {
	AllowedCIDRs     []string
	BlockedCIDRs     []string
	AllowedCountries []string
	BlockedCountries []string
	CrowdSec         CrowdSecChecker
	CrowdSecMode     CrowdSecMode
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

// IsObserveOnly returns true when v is a CrowdSec verdict and the filter is in
// observe mode. Callers should log the verdict but not block the request.
func (f *Filter) IsObserveOnly(v Verdict) bool {
	if f == nil {
		return false
	}
	return v.IsCrowdSec() && f.CrowdSecMode == CrowdSecObserve
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

	if v := f.checkCIDR(addr); v != Allow {
		return v
	}
	if v := f.checkCountry(addr, geo); v != Allow {
		return v
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
