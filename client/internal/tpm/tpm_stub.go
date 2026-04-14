//go:build !linux && !windows && !darwin

package tpm

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
)

var errNotSupported = errors.New("tpm: hardware security module not supported on this platform")

// StubProvider is returned by NewPlatformProvider on unsupported platforms (e.g. iOS, Android, js/wasm).
// Available() always returns false so callers fall back to legacy authentication.
type StubProvider struct{}

func (StubProvider) Available() bool                                                            { return false }
func (StubProvider) GenerateKey(_ context.Context, _ string) (crypto.Signer, error)            { return nil, errNotSupported }
func (StubProvider) LoadKey(_ context.Context, _ string) (crypto.Signer, error)                { return nil, errNotSupported }
func (StubProvider) StoreCert(_ context.Context, _ string, _ *x509.Certificate) error          { return errNotSupported }
func (StubProvider) LoadCert(_ context.Context, _ string) (*x509.Certificate, error)           { return nil, errNotSupported }
func (StubProvider) AttestationProof(_ context.Context, _ string) (*AttestationProof, error)   { return nil, errNotSupported }
func (StubProvider) ActivateCredential(_ context.Context, _ []byte) ([]byte, error)            { return nil, errNotSupported }

// NewPlatformProvider returns the stub on unsupported platforms.
// The stateDir argument is accepted for API compatibility with other platform providers but ignored.
func NewPlatformProvider(_ ...string) Provider {
	return StubProvider{}
}
