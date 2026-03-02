package ca

import (
	"context"
	"crypto/x509"
)

// SigningResult holds the output of a certificate signing operation.
type SigningResult struct {
	CertPEM  []byte
	ChainPEM []byte
}

// CertSigner is a backend-agnostic interface for signing certificate requests.
// Implementations include InternalCASigner (self-signed root CA) and
// ACMEPersistSigner (stub for future ACME DNS-PERSIST-01).
type CertSigner interface {
	// Sign signs the given CSR and returns the issued certificate and chain in PEM format.
	// peerFQDN is the expected FQDN that must match the CSR's DNSNames.
	// If wildcard is true, a wildcard SAN (*.peerFQDN) is added.
	Sign(ctx context.Context, csr *x509.CertificateRequest, peerFQDN string, wildcard bool) (*SigningResult, error)

	// Type returns the signer type identifier (e.g., "internal", "acme").
	Type() string
}
