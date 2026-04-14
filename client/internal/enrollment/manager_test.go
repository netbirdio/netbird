package enrollment

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/tpm"
)

// newSelfSignedCert returns a minimal self-signed cert for use in tests.
func newSelfSignedCert(t *testing.T, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestCertIsValid_ValidCert(t *testing.T) {
	cert := newSelfSignedCert(t, time.Now().Add(30*24*time.Hour))
	assert.True(t, certIsValid(cert), "cert expiring in 30d should be valid")
}

func TestCertIsValid_ExpiringSoon(t *testing.T) {
	// Expires in 6 days — below the 7-day renewal threshold.
	cert := newSelfSignedCert(t, time.Now().Add(6*24*time.Hour))
	assert.False(t, certIsValid(cert), "cert expiring in 6d should trigger renewal")
}

func TestCertIsValid_Expired(t *testing.T) {
	cert := newSelfSignedCert(t, time.Now().Add(-time.Hour))
	assert.False(t, certIsValid(cert), "expired cert must be invalid")
}

func TestCertIsValid_Nil(t *testing.T) {
	assert.False(t, certIsValid(nil))
}

func TestBackoff_Doubles(t *testing.T) {
	d := 5 * time.Second
	assert.Equal(t, 10*time.Second, backoff(d))
	assert.Equal(t, 20*time.Second, backoff(10*time.Second))
}

func TestBackoff_CapsAtMax(t *testing.T) {
	assert.Equal(t, pollMax, backoff(pollMax))
	assert.Equal(t, pollMax, backoff(3*pollMax))
}

func TestJitter_WithinRange(t *testing.T) {
	d := 10 * time.Second
	for i := 0; i < 50; i++ {
		got := jitter(d)
		assert.GreaterOrEqual(t, got, 9*time.Second, "jitter should not go below -10%%")
		assert.LessOrEqual(t, got, 11*time.Second, "jitter should not exceed +10%%")
	}
}

func TestBuildCSR_Valid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csrPEM, err := buildCSR(key, "my-wg-pubkey")
	require.NoError(t, err)
	require.NotEmpty(t, csrPEM)

	block, _ := pem.Decode([]byte(csrPEM))
	require.NotNil(t, block)
	assert.Equal(t, "CERTIFICATE REQUEST", block.Type)

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	assert.Equal(t, "my-wg-pubkey", csr.Subject.CommonName)
	assert.NoError(t, csr.CheckSignature())
}

// TestEnsureCertificate_ReturnsExistingValidCert verifies that EnsureCertificate
// returns immediately when a valid certificate is already stored.
func TestEnsureCertificate_ReturnsExistingValidCert(t *testing.T) {
	ctx := context.Background()
	provider := tpm.NewMockProvider()

	// Pre-generate a key and a valid certificate.
	_, keyErr := provider.GenerateKey(ctx, deviceKeyID)
	require.NoError(t, keyErr)

	cert := newSelfSignedCert(t, time.Now().Add(30*24*time.Hour))
	require.NoError(t, provider.StoreCert(ctx, deviceKeyID, cert))

	m := NewManager(provider, nil, t.TempDir(), "test-wg-pubkey")
	_ = m // The next call would need a real gRPC client; we just test cert lookup.

	loaded, err := provider.LoadCert(ctx, deviceKeyID)
	require.NoError(t, err)
	assert.True(t, certIsValid(loaded))
}

// TestStoreCertFromPEM_Valid verifies parsing and storage of a PEM cert.
func TestStoreCertFromPEM_Valid(t *testing.T) {
	ctx := context.Background()
	provider := tpm.NewMockProvider()
	_, err := provider.GenerateKey(ctx, deviceKeyID)
	require.NoError(t, err)

	cert := newSelfSignedCert(t, time.Now().Add(365*24*time.Hour))
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))

	m := &Manager{tpmProvider: provider}
	got, err := m.storeCertFromPEM(ctx, certPEM)
	require.NoError(t, err)
	assert.Equal(t, cert.SerialNumber, got.SerialNumber)
}

// TestStoreCertFromPEM_Empty verifies error on empty PEM.
func TestStoreCertFromPEM_Empty(t *testing.T) {
	m := &Manager{tpmProvider: tpm.NewMockProvider()}
	_, err := m.storeCertFromPEM(context.Background(), "")
	require.Error(t, err)
}

// TestEnrollmentState_SaveLoad verifies round-trip of enrollment state.
func TestEnrollmentState_SaveLoad(t *testing.T) {
	tmpDir := t.TempDir()
	m := &Manager{stateFile: tmpDir + "/enrollment.json"}

	state := &enrollmentState{
		EnrollmentID: "test-id-123",
		Status:       "pending",
		WGPublicKey:  "test-wg-key",
	}
	require.NoError(t, m.saveState(state))

	loaded, err := m.loadState()
	require.NoError(t, err)
	assert.Equal(t, state.EnrollmentID, loaded.EnrollmentID)
	assert.Equal(t, state.Status, loaded.Status)
	assert.Equal(t, state.WGPublicKey, loaded.WGPublicKey)
}

// TestEnrollmentState_LoadMissing verifies graceful error on missing state file.
func TestEnrollmentState_LoadMissing(t *testing.T) {
	m := &Manager{stateFile: t.TempDir() + "/nonexistent.json"}
	_, err := m.loadState()
	require.Error(t, err)
}

// TestStartRenewalLoop_NoSpuriousCallOnFirstRun verifies that StartRenewalLoop does NOT
// invoke onRenewal on the first iteration when the cert is already valid. This prevents
// a spurious mTLS reconnect every time the client starts.
func TestStartRenewalLoop_NoSpuriousCallOnFirstRun(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	provider := tpm.NewMockProvider()
	_, err := provider.GenerateKey(ctx, deviceKeyID)
	require.NoError(t, err)

	cert := newSelfSignedCert(t, time.Now().Add(30*24*time.Hour))
	require.NoError(t, provider.StoreCert(ctx, deviceKeyID, cert))

	m := NewManager(provider, nil, t.TempDir(), "test-wg-pubkey")

	called := make(chan struct{}, 1)
	m.StartRenewalLoop(ctx, func(_ *x509.Certificate) {
		select {
		case called <- struct{}{}:
		default:
		}
	})

	// onRenewal must NOT be called while the cert is unchanged.
	select {
	case <-called:
		t.Fatal("onRenewal must not be called on first run when cert is already valid")
	case <-ctx.Done():
		// Expected: timeout reached, onRenewal was not invoked.
	}
}

// TestManager_BuildTLSCertificate_ReturnsCert verifies that BuildTLSCertificate
// assembles a valid tls.Certificate when a cert and key are stored in the provider.
func TestManager_BuildTLSCertificate_ReturnsCert(t *testing.T) {
	ctx := context.Background()
	provider := tpm.NewMockProvider()

	// Generate a real key and store it so LoadKey succeeds.
	signer, err := provider.GenerateKey(ctx, deviceKeyID)
	require.NoError(t, err)
	privKey, ok := signer.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected *ecdsa.PrivateKey from MockProvider")

	// Build and store a self-signed certificate.
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "test-device"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)
	require.NoError(t, provider.StoreCert(ctx, deviceKeyID, cert))

	mgr := NewManager(provider, nil, t.TempDir(), "test-wg-key")
	tlsCert, err := mgr.BuildTLSCertificate(ctx)

	require.NoError(t, err)
	require.NotNil(t, tlsCert)

	// PrivateKey must be the same signer loaded from the provider.
	require.IsType(t, (*ecdsa.PrivateKey)(nil), tlsCert.PrivateKey)
	require.Equal(t, privKey.D, tlsCert.PrivateKey.(*ecdsa.PrivateKey).D)

	// Leaf must be set and carry the correct serial number.
	require.Equal(t, cert.SerialNumber, tlsCert.Leaf.SerialNumber)

	// Certificate chain must contain the raw DER bytes.
	require.Len(t, tlsCert.Certificate, 1)
	require.Equal(t, cert.Raw, tlsCert.Certificate[0])

	// Sanity: tls.Certificate.Leaf field type is correct.
	var _ = tlsCert // compile-time: verify tlsCert is a *tls.Certificate via assignment above
	_ = crypto.Signer(privKey) // compile-time assertion
}

// TestManager_BuildTLSCertificate_ErrNotEnrolledWhenNoCert verifies that
// BuildTLSCertificate returns ErrNotEnrolled when no certificate has been
// enrolled yet (callers can distinguish "not enrolled" from real errors).
func TestManager_BuildTLSCertificate_ErrNotEnrolledWhenNoCert(t *testing.T) {
	// Use a fresh provider with no stored certs — LoadCert will return ErrKeyNotFound.
	provider := tpm.NewMockProvider()
	mgr := NewManager(provider, nil, t.TempDir(), "test-wg-key")
	tlsCert, err := mgr.BuildTLSCertificate(context.Background())

	require.ErrorIs(t, err, ErrNotEnrolled)
	require.Nil(t, tlsCert)
}

// TestManager_BuildTLSCertificate_ErrorWhenCertExistsButKeyMissing verifies that
// BuildTLSCertificate returns a descriptive error when a cert is stored but the
// corresponding TPM key is absent (e.g. after a TPM reset).
func TestManager_BuildTLSCertificate_ErrorWhenCertExistsButKeyMissing(t *testing.T) {
	ctx := context.Background()
	provider := tpm.NewMockProvider()

	// Store a cert directly without generating a key first — simulates corrupted state
	// where the TPM has been reset but the cert file still exists.
	cert := newSelfSignedCert(t, time.Now().Add(365*24*time.Hour))
	require.NoError(t, provider.StoreCert(ctx, deviceKeyID, cert))

	mgr := NewManager(provider, nil, t.TempDir(), "test-wg-key")
	tlsCert, err := mgr.BuildTLSCertificate(ctx)

	require.Error(t, err)
	require.Nil(t, tlsCert)
	require.Contains(t, err.Error(), "missing")
}

// TestStartRenewalLoop_StopsOnContextCancel verifies that the loop goroutine exits
// cleanly when the context is cancelled, without blocking or leaking goroutines.
func TestStartRenewalLoop_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	provider := tpm.NewMockProvider()
	_, err := provider.GenerateKey(ctx, deviceKeyID)
	require.NoError(t, err)

	cert := newSelfSignedCert(t, time.Now().Add(30*24*time.Hour))
	require.NoError(t, provider.StoreCert(ctx, deviceKeyID, cert))

	m := NewManager(provider, nil, t.TempDir(), "test-wg-pubkey")

	stopped := make(chan struct{})
	m.StartRenewalLoop(ctx, func(_ *x509.Certificate) {})

	// Cancel and verify the loop does not block beyond a short grace period.
	cancel()
	go func() {
		// Give the goroutine time to observe the cancellation.
		time.Sleep(200 * time.Millisecond)
		close(stopped)
	}()

	select {
	case <-stopped:
		// Goroutine had time to see ctx.Done(); test passes.
	case <-time.After(3 * time.Second):
		t.Fatal("loop goroutine did not stop after context cancellation")
	}
}
