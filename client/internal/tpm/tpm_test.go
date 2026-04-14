package tpm_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/tpm"
)

// newTestCert builds a minimal self-signed certificate for use in StoreCert/LoadCert tests.
func newTestCert(t *testing.T, signer crypto.Signer) *x509.Certificate {
	t.Helper()

	pub := signer.Public()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test-device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, signer)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestMockProvider_Available(t *testing.T) {
	p := tpm.NewMockProvider()
	assert.True(t, p.Available())

	unavailable := tpm.NewUnavailableMockProvider()
	assert.False(t, unavailable.Available())
}

func TestMockProvider_GenerateKey_Idempotent(t *testing.T) {
	ctx := context.Background()
	p := tpm.NewMockProvider()

	key1, err := p.GenerateKey(ctx, "device-key")
	require.NoError(t, err)
	require.NotNil(t, key1)

	// Second call with same keyID must return the same key.
	key2, err := p.GenerateKey(ctx, "device-key")
	require.NoError(t, err)

	assert.Equal(t, key1.Public(), key2.Public(),
		"GenerateKey must be idempotent: same keyID returns same key")
}

func TestMockProvider_GenerateKey_DifferentIDs(t *testing.T) {
	ctx := context.Background()
	p := tpm.NewMockProvider()

	key1, err := p.GenerateKey(ctx, "key-a")
	require.NoError(t, err)

	key2, err := p.GenerateKey(ctx, "key-b")
	require.NoError(t, err)

	assert.NotEqual(t, key1.Public(), key2.Public(),
		"different keyIDs must produce distinct keys")
}

func TestMockProvider_LoadKey_NotFound(t *testing.T) {
	ctx := context.Background()
	p := tpm.NewMockProvider()

	_, err := p.LoadKey(ctx, "nonexistent")
	assert.ErrorIs(t, err, tpm.ErrKeyNotFound)
}

func TestMockProvider_LoadKey_AfterGenerate(t *testing.T) {
	ctx := context.Background()
	p := tpm.NewMockProvider()

	generated, err := p.GenerateKey(ctx, "my-key")
	require.NoError(t, err)

	loaded, err := p.LoadKey(ctx, "my-key")
	require.NoError(t, err)

	assert.Equal(t, generated.Public(), loaded.Public(),
		"LoadKey must return the same key that was generated")
}

func TestMockProvider_Sign_ECDSARoundtrip(t *testing.T) {
	ctx := context.Background()
	p := tpm.NewMockProvider()

	signer, err := p.GenerateKey(ctx, "sign-key")
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("hello netbird"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)

	ecPub, ok := signer.Public().(*ecdsa.PublicKey)
	require.True(t, ok, "key must be ECDSA")
	assert.True(t, ecdsa.VerifyASN1(ecPub, digest[:], sig),
		"ECDSA signature must verify with the corresponding public key")
}

func TestMockProvider_StoreCert_LoadCert_Roundtrip(t *testing.T) {
	ctx := context.Background()
	p := tpm.NewMockProvider()

	signer, err := p.GenerateKey(ctx, "cert-key")
	require.NoError(t, err)

	cert := newTestCert(t, signer)
	err = p.StoreCert(ctx, "cert-key", cert)
	require.NoError(t, err)

	loaded, err := p.LoadCert(ctx, "cert-key")
	require.NoError(t, err)

	assert.Equal(t, cert.SerialNumber, loaded.SerialNumber)
	assert.Equal(t, cert.Subject.CommonName, loaded.Subject.CommonName)
}

func TestMockProvider_LoadCert_NotFound(t *testing.T) {
	ctx := context.Background()
	p := tpm.NewMockProvider()

	_, err := p.LoadCert(ctx, "no-cert")
	assert.ErrorIs(t, err, tpm.ErrKeyNotFound)
}

func TestMockProvider_StoreCert_Overwrite(t *testing.T) {
	ctx := context.Background()
	p := tpm.NewMockProvider()

	signer, err := p.GenerateKey(ctx, "overwrite-key")
	require.NoError(t, err)

	cert1 := newTestCert(t, signer)
	require.NoError(t, p.StoreCert(ctx, "overwrite-key", cert1))

	signer2, err := p.GenerateKey(ctx, "overwrite-key-2")
	require.NoError(t, err)
	cert2 := newTestCert(t, signer2)
	require.NoError(t, p.StoreCert(ctx, "overwrite-key", cert2))

	loaded, err := p.LoadCert(ctx, "overwrite-key")
	require.NoError(t, err)

	assert.Equal(t, cert2.SerialNumber, loaded.SerialNumber,
		"StoreCert must overwrite the previous certificate")
}

func TestMockProvider_AttestationProof_Default(t *testing.T) {
	ctx := context.Background()
	p := tpm.NewMockProvider()

	_, err := p.GenerateKey(ctx, "attest-key")
	require.NoError(t, err)

	proof, err := p.AttestationProof(ctx, "attest-key")
	require.NoError(t, err)
	require.NotNil(t, proof)

	assert.NotEmpty(t, proof.EKCert)
	assert.NotEmpty(t, proof.AKPublic)
	assert.NotEmpty(t, proof.CertifyInfo)
	assert.NotEmpty(t, proof.Signature)
}

func TestMockProvider_AttestationProof_CustomFunc(t *testing.T) {
	ctx := context.Background()
	p := tpm.NewMockProvider()
	p.AttestationProofFunc = func(_ context.Context, _ string) (*tpm.AttestationProof, error) {
		return nil, tpm.ErrAttestationNotSupported
	}

	_, err := p.AttestationProof(ctx, "any-key")
	assert.ErrorIs(t, err, tpm.ErrAttestationNotSupported)
}

func TestMockProvider_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	p := tpm.NewMockProvider()

	// Generate key once upfront.
	_, err := p.GenerateKey(ctx, "concurrent-key")
	require.NoError(t, err)

	done := make(chan struct{})
	for i := 0; i < 20; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_, _ = p.GenerateKey(ctx, "concurrent-key")
			_, _ = p.LoadKey(ctx, "concurrent-key")
		}()
	}
	for i := 0; i < 20; i++ {
		<-done
	}
}

// TestProvider_InterfaceCompliance verifies that MockProvider implements Provider at compile time.
func TestProvider_InterfaceCompliance(t *testing.T) {
	var _ tpm.Provider = (*tpm.MockProvider)(nil)
}

func TestMockProvider_RejectsInvalidKeyID(t *testing.T) {
	ctx := context.Background()
	p := tpm.NewMockProvider()

	invalidIDs := []string{
		"",
		"../etc/passwd",
		"key with spaces",
		"key/slash",
		"key\x00null",
		"this-key-id-is-way-too-long-to-be-valid-because-it-exceeds-sixty-four-characters-in-length",
	}
	for _, id := range invalidIDs {
		t.Run(id, func(t *testing.T) {
			_, err := p.GenerateKey(ctx, id)
			assert.Error(t, err, "GenerateKey must reject invalid keyID %q", id)
		})
	}
}

func TestMockProvider_AcceptsValidKeyID(t *testing.T) {
	ctx := context.Background()
	p := tpm.NewMockProvider()

	validIDs := []string{
		"device-key",
		"device_key",
		"key123",
		"KEY-UPPER",
		"a",
		"a-b-c_1-2-3",
	}
	for _, id := range validIDs {
		t.Run(id, func(t *testing.T) {
			_, err := p.GenerateKey(ctx, id)
			assert.NoError(t, err, "GenerateKey must accept valid keyID %q", id)
		})
	}
}
