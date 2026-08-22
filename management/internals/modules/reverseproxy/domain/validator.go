package domain

import (
	"context"
	"net"
	"strings"

	log "github.com/sirupsen/logrus"
)

type resolver interface {
	LookupCNAME(context.Context, string) (string, error)
}

type Validator struct {
	Resolver resolver
}

// NewValidator initializes a validator with a specific DNS Resolver.
// If a Validator is used without specifying a Resolver, then it will
// use the net.DefaultResolver.
func NewValidator(resolver resolver) *Validator {
	return &Validator{
		Resolver: resolver,
	}
}

// IsValid looks up the CNAME record for the passed domain with a prefix
// and compares it against the acceptable domains.
// If the returned CNAME matches any accepted domain, it will return true,
// otherwise, including in the event of a DNS error, it will return false.
// The comparison is very simple, so wildcards will not match if included
// in the acceptable domain list.
func (v *Validator) IsValid(ctx context.Context, domain string, accept []string) bool {
	_, valid := v.ValidateWithCluster(ctx, domain, accept)
	return valid
}

// ValidateWithCluster validates a custom domain and returns the matched cluster address.
// Returns the cluster address and true if valid, or empty string and false if invalid.
func (v *Validator) ValidateWithCluster(ctx context.Context, domain string, accept []string) (string, bool) {
	if v.Resolver == nil {
		v.Resolver = net.DefaultResolver
	}

	// For wildcard domains (e.g. *.example.com), validate at the apex (validation.example.com)
	validationBase := domain
	if strings.HasPrefix(domain, "*.") {
		validationBase = domain[2:]
	}
	lookupDomain := "validation." + validationBase
	log.WithFields(log.Fields{
		"domain":       domain,
		"lookupDomain": lookupDomain,
		"acceptList":   accept,
	}).Debug("looking up CNAME for domain validation")

	cname, err := v.Resolver.LookupCNAME(ctx, lookupDomain)
	if err != nil {
		log.WithFields(log.Fields{
			"domain":       domain,
			"lookupDomain": lookupDomain,
		}).WithError(err).Warn("CNAME lookup failed for domain validation")
		return "", false
	}

	nakedCNAME := strings.TrimSuffix(cname, ".")
	log.WithFields(log.Fields{
		"domain":     domain,
		"cname":      cname,
		"nakedCNAME": nakedCNAME,
		"acceptList": accept,
	}).Debug("CNAME lookup result for domain validation")

	for _, acceptDomain := range accept {
		normalizedAccept := strings.TrimSuffix(acceptDomain, ".")
		if nakedCNAME == normalizedAccept {
			log.WithFields(log.Fields{
				"domain":  domain,
				"cname":   nakedCNAME,
				"cluster": acceptDomain,
			}).Info("domain CNAME matched cluster")
			return acceptDomain, true
		}
	}

	log.WithFields(log.Fields{
		"domain":     domain,
		"cname":      nakedCNAME,
		"acceptList": accept,
	}).Warn("domain CNAME does not match any accepted cluster")
	return "", false
}
