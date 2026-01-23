package mtls

// Machine Tunnel Fork - mTLS Identity Types and Validation
// This package defines types shared between server and grpc packages to avoid import cycles.

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
)

// mtlsIdentityKeyType is the context key type for mTLS identity
type mtlsIdentityKeyType struct{}

// IdentityKey is the context key for mTLS identity
var IdentityKey = mtlsIdentityKeyType{}

// Identity represents the extracted identity from a client certificate
type Identity struct {
	// DNSName is the primary identity from SAN DNSName (e.g., "hostname.domain.local")
	DNSName string
	// Hostname extracted from DNSName (e.g., "hostname")
	Hostname string
	// Domain extracted from DNSName (e.g., "domain.local")
	Domain string
	// MatchedDomain is the AllowedDomain that matched (for audit logging)
	MatchedDomain string
	// AccountID is the account UUID from domain mapping (CRITICAL for Multi-Tenant isolation!)
	AccountID string
	// IssuerFingerprint is SHA256 of the issuer certificate
	IssuerFingerprint string
	// SerialNumber of the client certificate
	SerialNumber string
	// TemplateOID if present in certificate extensions (v2 extension)
	TemplateOID string
	// TemplateName if present in certificate extensions (v1 extension, BMPString decoded)
	TemplateName string
	// PeerType determined from template: "machine", "user", or "unknown"
	PeerType string
}

// GetIdentity retrieves the mTLS identity from context.
// Returns nil if no mTLS identity is present (e.g., token auth was used).
func GetIdentity(ctx context.Context) *Identity {
	identity, ok := ctx.Value(IdentityKey).(*Identity)
	if !ok {
		return nil
	}
	return identity
}

// WithIdentity returns a new context with the mTLS identity attached.
func WithIdentity(ctx context.Context, identity *Identity) context.Context {
	return context.WithValue(ctx, IdentityKey, identity)
}

// ValidatorConfig holds configuration for mTLS validation.
// This is set during server initialization.
type ValidatorConfig struct {
	// AccountAllowedIssuers maps account IDs to their allowed CA issuer fingerprints (SHA256)
	// CRITICAL: If set for an account, only certificates from these CAs are accepted
	// If empty for an account, issuer validation is SKIPPED (warned, NOT RECOMMENDED for production!)
	AccountAllowedIssuers map[string][]string
}

// globalValidatorConfig is the server-wide mTLS validator configuration.
var globalValidatorConfig *ValidatorConfig

// SetValidatorConfig sets the global mTLS validator configuration.
// Must be called during server initialization.
func SetValidatorConfig(cfg *ValidatorConfig) {
	globalValidatorConfig = cfg
	if cfg != nil {
		log.Infof("mTLS validator config loaded: %d accounts with issuer allowlists",
			len(cfg.AccountAllowedIssuers))
	}
}

// ValidateIssuerCA validates that the certificate issuer is authorized for the given account.
// CRITICAL: This is a security boundary for multi-tenant isolation!
// Uses SHA256 fingerprint comparison (NOT string matching on DN which can be spoofed!)
//
// Returns nil if issuer is valid, error otherwise.
// Per Security Review: Empty allowlist = DENY (not any-CA!) for production safety.
func ValidateIssuerCA(accountID, issuerFingerprint string) error {
	if globalValidatorConfig == nil {
		// Config not set - allow for backwards compatibility during testing
		// In production, this should be configured
		log.Warnf("mTLS validator config not initialized - skipping issuer validation (configure for production!)")
		return nil
	}

	// Get allowed issuers for this account
	allowedIssuers := globalValidatorConfig.AccountAllowedIssuers[accountID]

	// Security: Empty allowlist = DENY (fail-safe for production)
	// Per Security Review: Explicit configuration required, no "any CA" fallback
	if len(allowedIssuers) == 0 {
		log.Warnf("SECURITY: Account %s has no MTLSAccountAllowedIssuers configured - rejecting certificate (explicit config required)", accountID)
		return fmt.Errorf("no allowed CA issuers configured for account %s - explicit MTLSAccountAllowedIssuers configuration required", accountID)
	}

	// Normalize fingerprint for comparison (lowercase hex)
	normalizedFP := strings.ToLower(issuerFingerprint)

	// Check against allowed issuers
	for _, allowed := range allowedIssuers {
		if strings.ToLower(allowed) == normalizedFP {
			log.Debugf("Issuer CA validated for account %s (FP: %s...)", accountID, truncateFP(normalizedFP))
			return nil
		}
	}

	return fmt.Errorf("certificate issuer CA (FP: %s) not in allowed list for account %s", truncateFP(normalizedFP), accountID)
}

// truncateFP truncates a fingerprint for safe logging (first 16 chars).
func truncateFP(fp string) string {
	if len(fp) > 16 {
		return fp[:16] + "..."
	}
	return fp
}
