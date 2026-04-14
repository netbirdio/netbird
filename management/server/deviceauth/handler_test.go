package deviceauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/deviceauth"
	"github.com/netbirdio/netbird/management/server/types"
)

// buildTestCA generates a self-signed CA and returns (cert, key).
func buildTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

// buildTestCert issues a leaf certificate signed by the given CA.
func buildTestCert(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string, notAfter time.Time) *x509.Certificate {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, leafKey.Public(), caKey)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func newHandlerWithCA(t *testing.T) (*deviceauth.Handler, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	ca, key := buildTestCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	h := deviceauth.NewHandler(pool)
	return h, ca, key
}

// ─── VerifyPeerCert ──────────────────────────────────────────────────────────

func TestVerifyPeerCert_EmptyCerts_ReturnsNil(t *testing.T) {
	h, _, _ := newHandlerWithCA(t)
	assert.NoError(t, h.VerifyPeerCert(nil, nil))
}

func TestVerifyPeerCert_ValidCert_ReturnsNil(t *testing.T) {
	h, ca, key := newHandlerWithCA(t)
	cert := buildTestCert(t, ca, key, "my-wg-key", time.Now().Add(365*24*time.Hour))
	assert.NoError(t, h.VerifyPeerCert([][]byte{cert.Raw}, nil))
}

func TestVerifyPeerCert_ExpiredCert_ReturnsError(t *testing.T) {
	h, ca, key := newHandlerWithCA(t)
	cert := buildTestCert(t, ca, key, "my-wg-key", time.Now().Add(-time.Hour))
	err := h.VerifyPeerCert([][]byte{cert.Raw}, nil)
	require.Error(t, err)
}

func TestVerifyPeerCert_UnknownCA_ReturnsError(t *testing.T) {
	h, _, _ := newHandlerWithCA(t)

	// Create a different CA and sign a cert with it.
	otherCA, otherKey := buildTestCA(t)
	cert := buildTestCert(t, otherCA, otherKey, "peer", time.Now().Add(time.Hour))

	err := h.VerifyPeerCert([][]byte{cert.Raw}, nil)
	require.Error(t, err)
}

func TestVerifyPeerCert_MalformedDER_ReturnsError(t *testing.T) {
	h, _, _ := newHandlerWithCA(t)
	err := h.VerifyPeerCert([][]byte{[]byte("not-a-cert")}, nil)
	require.Error(t, err)
}

// ─── CheckDeviceAuth ──────────────────────────────────────────────────────────

func TestCheckDeviceAuth_ModeDisabled_NoCert_Pass(t *testing.T) {
	h, _, _ := newHandlerWithCA(t)
	settings := &types.DeviceAuthSettings{Mode: "disabled"}
	err := h.CheckDeviceAuth(context.Background(), "wg-key", false, nil, settings)
	assert.NoError(t, err)
}

func TestCheckDeviceAuth_ModeOptional_NoCert_Pass(t *testing.T) {
	h, _, _ := newHandlerWithCA(t)
	settings := &types.DeviceAuthSettings{Mode: "optional"}
	err := h.CheckDeviceAuth(context.Background(), "wg-key", false, nil, settings)
	assert.NoError(t, err)
}

func TestCheckDeviceAuth_ModeOptional_ValidCert_Pass(t *testing.T) {
	h, ca, key := newHandlerWithCA(t)
	cert := buildTestCert(t, ca, key, "wg-key", time.Now().Add(time.Hour))
	settings := &types.DeviceAuthSettings{Mode: "optional"}
	err := h.CheckDeviceAuth(context.Background(), "wg-key", true, cert, settings)
	assert.NoError(t, err)
}

func TestCheckDeviceAuth_ModeCertOnly_NoCert_Denied(t *testing.T) {
	h, _, _ := newHandlerWithCA(t)
	settings := &types.DeviceAuthSettings{Mode: "cert-only"}
	err := h.CheckDeviceAuth(context.Background(), "wg-key", false, nil, settings)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "device certificate required")
}

func TestCheckDeviceAuth_ModeCertOnly_ValidCert_Pass(t *testing.T) {
	h, ca, key := newHandlerWithCA(t)
	cert := buildTestCert(t, ca, key, "wg-key", time.Now().Add(time.Hour))
	settings := &types.DeviceAuthSettings{Mode: "cert-only"}
	err := h.CheckDeviceAuth(context.Background(), "wg-key", true, cert, settings)
	assert.NoError(t, err)
}

func TestCheckDeviceAuth_ModeCertAndSSO_NoCert_Denied(t *testing.T) {
	h, _, _ := newHandlerWithCA(t)
	settings := &types.DeviceAuthSettings{Mode: "cert-and-sso"}
	err := h.CheckDeviceAuth(context.Background(), "wg-key", false, nil, settings)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "device certificate required")
}

func TestCheckDeviceAuth_ModeCertAndSSO_ValidCert_Pass(t *testing.T) {
	h, ca, key := newHandlerWithCA(t)
	cert := buildTestCert(t, ca, key, "wg-key", time.Now().Add(time.Hour))
	settings := &types.DeviceAuthSettings{Mode: "cert-and-sso"}
	err := h.CheckDeviceAuth(context.Background(), "wg-key", true, cert, settings)
	assert.NoError(t, err)
}

// WG key mismatch: cert CN != wgPubKey.
func TestCheckDeviceAuth_CertCNMismatch_Denied(t *testing.T) {
	h, ca, key := newHandlerWithCA(t)
	// CN in the cert is "other-key", but we're checking against "my-wg-key".
	cert := buildTestCert(t, ca, key, "other-key", time.Now().Add(time.Hour))
	settings := &types.DeviceAuthSettings{Mode: "cert-only"}
	err := h.CheckDeviceAuth(context.Background(), "my-wg-key", true, cert, settings)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "certificate CN mismatch")
}

// NilSettings should behave like "disabled".
func TestCheckDeviceAuth_NilSettings_Pass(t *testing.T) {
	h, _, _ := newHandlerWithCA(t)
	err := h.CheckDeviceAuth(context.Background(), "wg-key", false, nil, nil)
	assert.NoError(t, err)
}

// Interface compliance.
func TestHandler_InterfaceCompliance(t *testing.T) {
	var _ deviceauth.DeviceAuthHandler = (*deviceauth.Handler)(nil)
}

// UpdateCertPool replaces the pool and affects subsequent verifications.
func TestHandler_UpdateCertPool(t *testing.T) {
	// Start with empty pool.
	h := deviceauth.NewHandler(x509.NewCertPool())

	ca, key := buildTestCA(t)
	cert := buildTestCert(t, ca, key, "peer", time.Now().Add(time.Hour))

	// Before update: unknown CA → error.
	assert.Error(t, h.VerifyPeerCert([][]byte{cert.Raw}, nil))

	// After adding CA to pool: should pass.
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	h.UpdateCertPool(pool)
	assert.NoError(t, h.VerifyPeerCert([][]byte{cert.Raw}, nil))
}
