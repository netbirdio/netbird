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

// GeoResolver resolves an IP address to geographic information.
type GeoResolver interface {
	LookupAddr(addr netip.Addr) geolocation.Result
	Available() bool
}

// Filter evaluates IP restrictions. CIDR checks are performed first
// (cheap), followed by country lookups (more expensive) only when needed.
type Filter struct {
	AllowedCIDRs     []netip.Prefix
	BlockedCIDRs     []netip.Prefix
	AllowedCountries []string
	BlockedCountries []string
}

// ParseFilter builds a Filter from the raw string slices. Returns nil
// if all slices are empty.
func ParseFilter(allowedCIDRs, blockedCIDRs, allowedCountries, blockedCountries []string) *Filter {
	if len(allowedCIDRs) == 0 && len(blockedCIDRs) == 0 &&
		len(allowedCountries) == 0 && len(blockedCountries) == 0 {
		return nil
	}

	f := &Filter{
		AllowedCountries: normalizeCountryCodes(allowedCountries),
		BlockedCountries: normalizeCountryCodes(blockedCountries),
	}
	for _, cidr := range allowedCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			log.Warnf("skip invalid allowed CIDR %q: %v", cidr, err)
			continue
		}
		f.AllowedCIDRs = append(f.AllowedCIDRs, prefix.Masked())
	}
	for _, cidr := range blockedCIDRs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			log.Warnf("skip invalid blocked CIDR %q: %v", cidr, err)
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
	default:
		return "unknown"
	}
}

// Check evaluates whether addr is permitted. CIDR rules are evaluated
// first because they are O(n) prefix comparisons. Country rules run
// only when CIDR checks pass and require a geo lookup.
func (f *Filter) Check(addr netip.Addr, geo GeoResolver) Verdict {
	if f == nil {
		return Allow
	}

	// Normalize v4-mapped-v6 (e.g. ::ffff:10.1.2.3) to plain v4 so that
	// IPv4 CIDR rules match regardless of how the address was received.
	addr = addr.Unmap()

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

// HasRestrictions returns true if any restriction rules are configured.
func (f *Filter) HasRestrictions() bool {
	if f == nil {
		return false
	}
	return len(f.AllowedCIDRs) > 0 || len(f.BlockedCIDRs) > 0 ||
		len(f.AllowedCountries) > 0 || len(f.BlockedCountries) > 0
}
