package domain

import (
	"context"
	"net"
	"strings"
)

type resolver interface {
	LookupCNAME(context.Context, string) (string, error)
}

type Validator struct {
	resolver resolver
}

// NewValidator initializes a validator with a specific DNS resolver.
// If a Validator is used without specifying a resolver, then it will
// use the net.DefaultResolver.
func NewValidator(resolver resolver) *Validator {
	return &Validator{
		resolver: resolver,
	}
}

// IsValid looks up the CNAME record for the passed domain and compares it
// against the acceptable domains.
// If the returned CNAME matches any accepted domain, it will return true,
// otherwise, including in the event of a DNS error, it will return false.
// The comparison is very simple, so wildcards will not match if included
// in the acceptable domain list.
func (v *Validator) IsValid(ctx context.Context, domain string, accept []string) bool {
	if v.resolver == nil {
		v.resolver = net.DefaultResolver
	}

	cname, err := v.resolver.LookupCNAME(ctx, domain)
	if err != nil {
		return false
	}

	// Remove a trailing "." from the CNAME (most people do not include the trailing "." in FQDN, so it is easier to strip this when comparing).
	nakedCNAME := strings.TrimSuffix(cname, ".")
	for _, domain := range accept {
		// Currently, the match is a very simple string comparison.
		if nakedCNAME == strings.TrimSuffix(domain, ".") {
			return true
		}
	}
	return false
}
