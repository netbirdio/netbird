package domain

import (
	"context"
	"errors"
	"fmt"
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

// ValidationReason classifies why a custom domain failed validation.
type ValidationReason string

const (
	ValidationReasonCNAMENotFound   ValidationReason = "cname_not_found"
	ValidationReasonCNAMEMismatch   ValidationReason = "cname_mismatch"
	ValidationReasonLookupFailed    ValidationReason = "lookup_failed"
	ValidationReasonExpired         ValidationReason = "validation_expired"
	ValidationReasonNoTargetCluster ValidationReason = "no_target_cluster"
)

// ValidationError is a validation failure whose message is safe to show to the user.
type ValidationError struct {
	Reason  ValidationReason
	Message string
}

// Error returns the user-facing message.
func (e *ValidationError) Error() string {
	return e.Message
}

// NewValidationError returns a ValidationError with a formatted message.
func NewValidationError(reason ValidationReason, format string, args ...any) *ValidationError {
	return &ValidationError{Reason: reason, Message: fmt.Sprintf(format, args...)}
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
	cluster, err := v.Validate(ctx, domain, accept)
	return cluster, err == nil
}

// Validate validates a custom domain and returns the matched cluster address.
// On failure it returns a *ValidationError whose message is safe to show to the user.
func (v *Validator) Validate(ctx context.Context, domain string, accept []string) (string, error) {
	if v.Resolver == nil {
		v.Resolver = net.DefaultResolver
	}

	lookupDomain := "validation." + domain
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
		// Never forward the resolver error: its text includes the resolver address.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return "", cnameNotFound(lookupDomain, accept)
		}
		return "", NewValidationError(ValidationReasonLookupFailed, "DNS lookup for %s failed; retry the validation", lookupDomain)
	}

	nakedCNAME := strings.TrimSuffix(cname, ".")
	// A name without a CNAME record resolves to itself.
	if strings.EqualFold(nakedCNAME, lookupDomain) {
		return "", cnameNotFound(lookupDomain, accept)
	}
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
			return acceptDomain, nil
		}
	}

	log.WithFields(log.Fields{
		"domain":     domain,
		"cname":      nakedCNAME,
		"acceptList": accept,
	}).Warn("domain CNAME does not match any accepted cluster")
	return "", NewValidationError(ValidationReasonCNAMEMismatch, "CNAME record %s points to %s; point it to %s",
		lookupDomain, nakedCNAME, strings.Join(accept, ", "))
}

func cnameNotFound(lookupDomain string, accept []string) *ValidationError {
	return NewValidationError(ValidationReasonCNAMENotFound, "no CNAME record found for %s; point it to %s",
		lookupDomain, strings.Join(accept, ", "))
}
