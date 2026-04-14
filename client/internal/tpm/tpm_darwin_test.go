//go:build darwin

package tpm_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/tpm"
)

func TestDarwinProvider_NewPlatformProvider(t *testing.T) {
	p := tpm.NewPlatformProvider(t.TempDir())
	require.NotNil(t, p)
}

func TestDarwinProvider_Available(t *testing.T) {
	p := tpm.NewPlatformProvider(t.TempDir())
	// Available() must be callable without panicking.
	// On Apple Silicon and Intel T2 Macs (all CI runners), SE is present.
	_ = p.Available()
}

func TestDarwinProvider_AttestationProof_NotSupported(t *testing.T) {
	ctx := context.Background()
	p := tpm.NewPlatformProvider(t.TempDir())

	_, err := p.AttestationProof(ctx, "any-key")
	assert.ErrorIs(t, err, tpm.ErrAttestationNotSupported,
		"macOS Secure Enclave must return ErrAttestationNotSupported for attestation proof")
}

func TestDarwinProvider_StoreCert_LoadCert_Roundtrip(t *testing.T) {
	ctx := context.Background()
	stateDir := t.TempDir()
	p := tpm.NewPlatformProvider(stateDir)

	// Use a mock key to generate a cert (StoreCert/LoadCert are filesystem-only).
	mock := tpm.NewMockProvider()
	signer, err := mock.GenerateKey(ctx, "cert-key")
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "darwin-device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	err = p.StoreCert(ctx, "device-key", cert)
	require.NoError(t, err)

	loaded, err := p.LoadCert(ctx, "device-key")
	require.NoError(t, err)

	assert.Equal(t, cert.SerialNumber, loaded.SerialNumber)
	assert.Equal(t, cert.Subject.CommonName, loaded.Subject.CommonName)
}

func TestDarwinProvider_LoadCert_NotFound(t *testing.T) {
	ctx := context.Background()
	p := tpm.NewPlatformProvider(t.TempDir())

	_, err := p.LoadCert(ctx, "nonexistent")
	assert.ErrorIs(t, err, tpm.ErrKeyNotFound)
}

func TestDarwinProvider_InterfaceCompliance(t *testing.T) {
	//nolint:staticcheck // QF1011: explicit type annotation verifies interface compliance at compile time
	var _ tpm.Provider = tpm.NewPlatformProvider()
}

func TestDarwinProvider_ActivateCredential_NotSupported(t *testing.T) {
	ctx := context.Background()
	p := tpm.NewPlatformProvider(t.TempDir())
	_, err := p.ActivateCredential(ctx, []byte("blob"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ActivateCredential not supported on Apple SE")
}

// TestDarwinProvider_CreateSEAttestation_KeyNotFound verifies that CreateSEAttestation
// returns a descriptive error when the key does not exist in the Keychain.
// This test does not require SE hardware.
func TestDarwinProvider_CreateSEAttestation_KeyNotFound(t *testing.T) {
	ctx := context.Background()
	p, ok := tpm.NewPlatformProvider(t.TempDir()).(interface {
		CreateSEAttestation(ctx context.Context, keyID string) ([][]byte, error)
	})
	require.True(t, ok, "darwinProvider must implement CreateSEAttestation")

	_, err := p.CreateSEAttestation(ctx, "nonexistent-key-id")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent-key-id")
}

// TestDarwinProvider_CreateSEAttestation_WithSEKey exercises the full attestation path
// on machines with a Secure Enclave chip (Apple Silicon or T2). Skips on Intel without T2.
func TestDarwinProvider_CreateSEAttestation_WithSEKey(t *testing.T) {
	ctx := context.Background()
	provider := tpm.NewPlatformProvider(t.TempDir())
	if !provider.Available() {
		t.Skip("Secure Enclave not available on this machine")
	}

	p, ok := provider.(interface {
		CreateSEAttestation(ctx context.Context, keyID string) ([][]byte, error)
	})
	require.True(t, ok, "darwinProvider must implement CreateSEAttestation")

	// Generate an SE key to attest.
	// Skip if the process lacks Keychain access entitlements (common in unsigned test binaries).
	_, err := provider.GenerateKey(ctx, "attest-test-key")
	if err != nil {
		t.Skipf("GenerateKey failed (likely missing Keychain entitlements in test binary): %v", err)
	}

	chain, err := p.CreateSEAttestation(ctx, "attest-test-key")
	require.NoError(t, err)
	require.NotEmpty(t, chain, "attestation chain must have at least one certificate")

	// Verify the leaf is a parseable DER certificate.
	_, err = x509.ParseCertificate(chain[0])
	require.NoError(t, err, "attestation leaf must be a valid DER certificate")
}
