// Package devicepki provides CA operations for device certificate authentication.
package devicepki

import (
	"context"
	"crypto/x509"
	"errors"
)

// maxHTTPResponseBytes caps how much data we read from external CA HTTP responses
// to prevent memory exhaustion from malicious or misbehaving servers.
const maxHTTPResponseBytes = 10 << 20 // 10 MiB

// ErrCANotFound is returned when no CA exists for an account.
var ErrCANotFound = errors.New("devicepki: CA not found")

// ErrInvalidCSR is returned when a CSR fails validation.
var ErrInvalidCSR = errors.New("devicepki: invalid certificate signing request")

// ErrNotImplemented is returned when a CA backend operation is not yet implemented.
var ErrNotImplemented = errors.New("devicepki: operation not implemented")

// CA is the interface that all certificate authority backends must implement.
// The built-in CA (BuiltinCA) generates a self-signed root per account.
// External CAs (Phase 3+) implement the same interface.
type CA interface {
	// GenerateCA creates a new self-signed root CA for the given account.
	// The returned PEM string should be persisted via TrustedCA store.
	GenerateCA(ctx context.Context, accountID string) (certPEM string, keyPEM string, err error)

	// SignCSR validates and signs a PKCS#10 CSR.
	// cn is the Common Name to embed (WireGuard public key).
	// validityDays controls the certificate's NotAfter.
	// Returns the signed certificate as DER bytes.
	SignCSR(ctx context.Context, csr *x509.CertificateRequest, cn string, validityDays int) (*x509.Certificate, error)

	// RevokeCert marks a certificate as revoked. The serial number is in decimal.
	RevokeCert(ctx context.Context, serial string) error

	// GenerateCRL returns a fresh DER-encoded CRL signed by the CA.
	GenerateCRL(ctx context.Context) ([]byte, error)

	// CACert returns the CA certificate for inclusion in trust stores.
	CACert(ctx context.Context) *x509.Certificate
}
