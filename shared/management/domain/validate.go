package domain

import (
	"fmt"
	"regexp"
	"strings"
)

const maxDomains = 32

var domainRegex = regexp.MustCompile(`^(?:\*\.)?(?:(?:xn--)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:xn--)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`)

// ValidateDomains checks if each domain in the list is valid and returns a punycode-encoded DomainList.
func ValidateDomains(domains []string) (List, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("domains list is empty")
	}
	if len(domains) > maxDomains {
		return nil, fmt.Errorf("domains list exceeds maximum allowed domains: %d", maxDomains)
	}

	var domainList List

	for _, d := range domains {
		validDomain, err := ToValidDomain(d)
		if err != nil {
			return nil, fmt.Errorf("invalid domain %s: %w", d, err)
		}
		domainList = append(domainList, validDomain)
	}
	return domainList, nil
}

// ValidateDomainsList checks if each domain in the list is valid
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

// IsValidDomain checks if the given domain is valid.
func IsValidDomain(domain string) bool {
	// handles length and idna conversion
	punycode, err := FromString(domain)
	if err != nil {
		return false
	}

	return domainRegex.MatchString(string(punycode))
}

// ToValidDomain converts a domain to a valid domain format.
func ToValidDomain(domain string) (Domain, error) {
	// handles length and idna conversion
	punycode, err := FromString(domain)
	if err != nil {
		return "", fmt.Errorf("convert domain to punycode: %s: %w", domain, err)
	}

	if !domainRegex.MatchString(string(punycode)) {
		return "", fmt.Errorf("invalid domain format: %s", domain)
	}

	return punycode, nil
}
