package service

import (
	"fmt"
	"net/netip"
	"strings"
)

const (
	maxCIDREntries    = 200
	maxCountryEntries = 50
)

func validateCrowdSecMode(mode string) error {
	switch mode {
	case "", "off", "enforce", "observe":
		return nil
	default:
		return fmt.Errorf("crowdsec_mode %q is invalid", mode)
	}
}

func validateAllowMatch(mode string) error {
	switch mode {
	case "", "all", "any":
		return nil
	default:
		return fmt.Errorf("allow_match %q is invalid", mode)
	}
}

func validateAppSecMode(mode string) error {
	switch mode {
	case "", "off", "enforce", "observe":
		return nil
	default:
		return fmt.Errorf("appsec_mode %q is invalid", mode)
	}
}

// appSecEnabled reports whether the mode asks for request inspection.
func appSecEnabled(mode string) bool {
	return mode == "enforce" || mode == "observe"
}

// validateAccessRestrictions validates and normalizes access restriction
// entries. Country codes are uppercased in place.
func validateAccessRestrictions(r *AccessRestrictions) error {
	if err := validateCrowdSecMode(r.CrowdSecMode); err != nil {
		return err
	}
	if err := validateAllowMatch(r.AllowMatch); err != nil {
		return err
	}
	if err := validateAppSecMode(r.AppSecMode); err != nil {
		return err
	}

	if len(r.AllowedCIDRs) > maxCIDREntries {
		return fmt.Errorf("allowed_cidrs: exceeds maximum of %d entries", maxCIDREntries)
	}
	if len(r.BlockedCIDRs) > maxCIDREntries {
		return fmt.Errorf("blocked_cidrs: exceeds maximum of %d entries", maxCIDREntries)
	}
	if len(r.AllowedCountries) > maxCountryEntries {
		return fmt.Errorf("allowed_countries: exceeds maximum of %d entries", maxCountryEntries)
	}
	if len(r.BlockedCountries) > maxCountryEntries {
		return fmt.Errorf("blocked_countries: exceeds maximum of %d entries", maxCountryEntries)
	}

	if err := validateCIDRList("allowed_cidrs", r.AllowedCIDRs); err != nil {
		return err
	}
	if err := validateCIDRList("blocked_cidrs", r.BlockedCIDRs); err != nil {
		return err
	}
	if err := normalizeCountryList("allowed_countries", r.AllowedCountries); err != nil {
		return err
	}
	return normalizeCountryList("blocked_countries", r.BlockedCountries)
}

func validateCIDRList(field string, cidrs []string) error {
	for i, raw := range cidrs {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return fmt.Errorf("%s[%d]: %w", field, i, err)
		}
		if prefix != prefix.Masked() {
			return fmt.Errorf("%s[%d]: %q has host bits set, use %s instead", field, i, raw, prefix.Masked())
		}
	}
	return nil
}

func normalizeCountryList(field string, codes []string) error {
	for i, code := range codes {
		if !isAlpha2Code(code) {
			return fmt.Errorf("%s[%d]: %q must be a 2-letter ISO 3166-1 alpha-2 code", field, i, code)
		}
		codes[i] = strings.ToUpper(code)
	}
	return nil
}

func isAlpha2Code(code string) bool {
	if len(code) != 2 {
		return false
	}
	for i := 0; i < len(code); i++ {
		c := code[i]
		if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}
