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
	if v.resolver == nil {
		v.resolver = net.DefaultResolver
	}

	cname, err := v.resolver.LookupCNAME(ctx, "validation."+domain)
	if err != nil {
		log.WithFields(log.Fields{
			"domain": domain,
		}).WithError(err).Error("Error resolving CNAME from resolver")
		return "", false
	}

	nakedCNAME := strings.TrimSuffix(cname, ".")
	for _, acceptDomain := range accept {
		normalizedAccept := strings.TrimSuffix(acceptDomain, ".")
		if nakedCNAME == normalizedAccept {
			return acceptDomain, true
		}
	}
	return "", false
}

// ExtractClusterFromFreeDomain extracts the cluster address from a free domain.
// Free domains have the format: <name>.<nonce>.<cluster> (e.g., myapp.abc123.eu.proxy.netbird.io)
// It matches the domain suffix against available clusters and returns the matching cluster.
func ExtractClusterFromFreeDomain(domain string, availableClusters []string) (string, bool) {
	for _, cluster := range availableClusters {
		if strings.HasSuffix(domain, "."+cluster) {
			return cluster, true
		}
	}
	return "", false
}
