package ca

import (
	"context"
	"crypto/x509"
	"fmt"
)

const (
	// SigningTypeACME is the identifier for the ACME DNS-PERSIST-01 signer.
	SigningTypeACME = "acme"
)

// ACMEPersistSigner is a stub implementation for the future ACME DNS-PERSIST-01 signing backend.
// It returns an error indicating the feature is not yet available.
type ACMEPersistSigner struct{}

// NewACMEPersistSigner creates a new ACMEPersistSigner stub.
func NewACMEPersistSigner() *ACMEPersistSigner {
	return &ACMEPersistSigner{}
}

// Sign is not implemented and returns an error.
func (s *ACMEPersistSigner) Sign(_ context.Context, _ *x509.CertificateRequest, _ string, _ bool) (*SigningResult, error) {
	return nil, fmt.Errorf("ACME DNS-PERSIST-01 signing is not yet available")
}

// Type returns the signer type identifier.
func (s *ACMEPersistSigner) Type() string {
	return SigningTypeACME
}
