package mtls

// Machine Tunnel Fork - mTLS Identity Types
// This package defines types shared between server and grpc packages to avoid import cycles.

import (
	"context"
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
