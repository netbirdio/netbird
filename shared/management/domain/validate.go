package domain

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
)

const maxFQDN = 32

var regexCache = map[string]*regexp.Regexp{}
var regexCacheMu sync.Mutex

var fqdnRegex = regexp.MustCompile(`^(?:(?:xn--)?[a-zA-Z0-9_](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)*(?:xn--)?[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?$`)

func buildDomainRegex(allowWildcard, allowSingleToplevel bool) *regexp.Regexp {
	key := fmt.Sprintf("%t:%t", allowWildcard, allowSingleToplevel)

	regexCacheMu.Lock()
	defer regexCacheMu.Unlock()

	if re, ok := regexCache[key]; ok {
		return re
	}

	var pattern strings.Builder
	pattern.WriteString("^")

	if allowWildcard {
		pattern.WriteString(`(?:\*\.)?`)
	}

	label := `(?:xn--)?[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?`

	if allowSingleToplevel {
		pattern.WriteString(label + `(?:\.` + label + `)*`)
	} else {
		pattern.WriteString(label + `(?:\.` + label + `)+`)
	}

	pattern.WriteString("$")

	re := regexp.MustCompile(pattern.String())
	regexCache[key] = re
	return re
}

// ValidateFQDNs checks if each domain in the list is valid and returns a punycode-encoded DomainList.
func ValidateFQDNs(fqdns []string) (List, error) {
	if len(fqdns) == 0 {
		return nil, fmt.Errorf("fqdns list is empty")
	}
	if len(fqdns) > maxFQDN {
		return nil, fmt.Errorf("fqdns list exceeds maximum allowed fqdns: %d", maxFQDN)
	}

	var domainList List

	for _, d := range fqdns {
		validDomain, err := ToValidFQDN(d)
		if err != nil {
			return nil, fmt.Errorf("invalid domain %s: %w", d, err)
		}
		domainList = append(domainList, validDomain)
	}
	return domainList, nil
}

// ValidateDomains checks if each domain in the list is valid and returns a punycode-encoded DomainList.
func ValidateDomains(domains []string) (List, error) {
	if len(domains) == 0 {
		return nil, fmt.Errorf("domains list is empty")
	}
	if len(domains) > maxFQDN {
		return nil, fmt.Errorf("domains list exceeds maximum allowed domains: %d", maxFQDN)
	}

	var domainList List

	for _, d := range domains {
		validDomain, err := ToValidDomain(d, true, true)
		if err != nil {
			return nil, fmt.Errorf("invalid domain %s: %w", d, err)
		}
		domainList = append(domainList, validDomain)
	}
	return domainList, nil
}

// ValidateFQDNsList checks if each domain in the list is valid
func ValidateFQDNsList(fqdns []string) error {
	if len(fqdns) == 0 {
		return nil
	}
	if len(fqdns) > maxFQDN {
		return fmt.Errorf("fqdns list exceeds maximum allowed fqdns: %d", maxFQDN)
	}

	for _, d := range fqdns {
		d := strings.ToLower(d)
		if !fqdnRegex.MatchString(d) {
			return fmt.Errorf("invalid fqdns format: %s", d)
		}
	}
	return nil
}

// IsValidDomain checks if the given domain is valid.
func IsValidDomain(domain string, allowWildcard, allowSingleToplevel bool) bool {
	// handles length and idna conversion
	punycode, err := FromString(domain)
	if err != nil {
		return false
	}

	domainRegex := buildDomainRegex(allowWildcard, allowSingleToplevel)
	return domainRegex.MatchString(string(punycode))
}

// ToValidDomain converts a domain to a valid domain format.
func ToValidDomain(domain string, allowWildcard, allowSingleToplevel bool) (Domain, error) {
	// handles length and idna conversion
	punycode, err := FromString(domain)
	if err != nil {
		return "", fmt.Errorf("convert domain to punycode: %s: %w", domain, err)
	}

	domainRegex := buildDomainRegex(allowWildcard, allowSingleToplevel)
	if !domainRegex.MatchString(string(punycode)) {
		return "", fmt.Errorf("invalid domain format: %s", domain)
	}

	return punycode, nil
}

// ToValidFQDN converts a domain to a valid fqdn format.
func ToValidFQDN(domain string) (Domain, error) {
	// handles length and idna conversion
	punycode, err := FromString(domain)
	if err != nil {
		return "", fmt.Errorf("convert domain to punycode: %s: %w", domain, err)
	}

	if !fqdnRegex.MatchString(string(punycode)) {
		return "", fmt.Errorf("invalid domain format: %s", domain)
	}

	return punycode, nil
}
