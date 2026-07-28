package domain

import (
	"fmt"
	"regexp"
	"strings"
)

const maxDomains = 32

var domainRegex = regexp.MustCompile(`^(?:\*\.)?(?:(?:xn--)?[a-zA-Z0-9_](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)*(?:xn--)?[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?$`)

// IsValidDomain checks if a single domain string is valid.
// Does not convert unicode to punycode - domain must already be ASCII/punycode.
// Allows wildcard prefix (*.example.com).
func IsValidDomain(domain string) bool {
	if domain == "" {
		return false
	}
	return domainRegex.MatchString(strings.ToLower(domain))
}

// IsValidDomainNoWildcard checks if a single domain string is valid without wildcard prefix.
// Use for zone domains and CNAME targets where wildcards are not allowed.
func IsValidDomainNoWildcard(domain string) bool {
	if domain == "" {
		return false
	}
	if strings.HasPrefix(domain, "*.") {
		return false
	}
	return domainRegex.MatchString(strings.ToLower(domain))
}

// ValidateDomains validates domains and converts unicode to punycode.
// Allows wildcard prefix (*.example.com). Maximum 32 domains.
func ValidateDomains(domains []string) (List, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("domains list is empty")
	}
	if len(domains) > maxDomains {
		return nil, fmt.Errorf("domains list exceeds maximum allowed domains: %d", maxDomains)
	}

	var domainList List

	for _, d := range domains {
		// handles length and idna conversion
		punycode, err := FromString(d)
		if err != nil {
			return domainList, fmt.Errorf("convert domain to punycode: %s: %w", d, err)
		}

		if !domainRegex.MatchString(string(punycode)) {
			return domainList, fmt.Errorf("invalid domain format: %s", d)
		}

		domainList = append(domainList, punycode)
	}
	return domainList, nil
}

// ValidateDomainsList validates domains without punycode conversion.
// Use this for domains that must already be in ASCII/punycode format (e.g., extra DNS labels).
// Unlike ValidateDomains, this does not convert unicode to punycode - unicode domains will fail.
// Allows wildcard prefix (*.example.com). Maximum 32 domains.
func ValidateDomainsList(domains []string) error {
	if len(domains) == 0 {
		return nil
	}
	if len(domains) > maxDomains {
		return fmt.Errorf("domains list exceeds maximum allowed domains: %d", maxDomains)
	}

	for _, d := range domains {
		d := strings.ToLower(d)
		if !domainRegex.MatchString(d) {
			return fmt.Errorf("invalid domain format: %s", d)
		}
	}
	return nil
}
