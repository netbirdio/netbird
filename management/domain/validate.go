package domain

import (
	"fmt"
	"regexp"
	"strings"
)

const maxDomains = 32

var domainRegex = regexp.MustCompile(`^(?:\*\.)?(?:(?:xn--)?[a-zA-Z0-9_](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)*(?:xn--)?[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?$`)

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
