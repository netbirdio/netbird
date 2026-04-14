package grpc

import (
	"context"
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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	nbstatus "github.com/netbirdio/netbird/shared/management/status"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// stubDeviceCertStore is a test double for deviceCertStore.
type stubDeviceCertStore struct {
	cert       *types.DeviceCertificate
	err        error
	trustedCAs []*types.TrustedCA
	caErr      error
}

func (s *stubDeviceCertStore) GetDeviceCertificateByWGKey(_ context.Context, _ store.LockingStrength, _, _ string) (*types.DeviceCertificate, error) {
	return s.cert, s.err
}

func (s *stubDeviceCertStore) ListTrustedCAs(_ context.Context, _ store.LockingStrength, _ string) ([]*types.TrustedCA, error) {
	return s.trustedCAs, s.caErr
}

// caFixture holds a generated CA key pair with its PEM-encoded certificate.
type caFixture struct {
	key     *ecdsa.PrivateKey
	cert    *x509.Certificate
	certPEM string // PEM-encoded CA certificate for storage in TrustedCA
}

// makeCA generates a self-signed CA certificate suitable for use as a TrustedCA.
func makeCA(t *testing.T) caFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return caFixture{key: key, cert: caCert, certPEM: certPEM}
}

// makeLeafCert generates a leaf certificate signed by the given CA.
func makeLeafCert(t *testing.T, serial *big.Int, ca caFixture) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-peer"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// selfSignedCert generates a self-signed x509 cert with the given serial number.
// Use for tests where the cert is tracked in the store (revocation checks).
// For external-CA tests use makeCA + makeLeafCert instead.
func selfSignedCert(t *testing.T, serial *big.Int) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-peer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func TestCheckCertRevocation_NilCert_Allowed(t *testing.T) {
	st := &stubDeviceCertStore{}
	err := checkCertRevocation(context.Background(), st, "acct1", "wg-key", nil)
	assert.NoError(t, err)
}

// ─── H-5: cross-account certificate spoofing prevention ──────────────────────

// TestCheckCertRevocation_ExternalCA_InAccountPool_Allowed verifies that a cert
// issued by a CA registered in THIS account is allowed when not tracked in the store.
func TestCheckCertRevocation_ExternalCA_InAccountPool_Allowed(t *testing.T) {
	ca := makeCA(t)
	leafCert := makeLeafCert(t, big.NewInt(42), ca)

	st := &stubDeviceCertStore{
		err: nbstatus.Errorf(nbstatus.NotFound, "not found"),
		trustedCAs: []*types.TrustedCA{
			{PEM: ca.certPEM},
		},
	}

	err := checkCertRevocation(context.Background(), st, "acct1", "wg-key", leafCert)
	assert.NoError(t, err)
}

// TestCheckCertRevocation_ExternalCA_NotInAccountPool_Denied verifies H-5:
// a cert issued by a foreign CA (registered in a different account) is denied.
func TestCheckCertRevocation_ExternalCA_NotInAccountPool_Denied(t *testing.T) {
	foreignCA := makeCA(t)
	leafCert := makeLeafCert(t, big.NewInt(99), foreignCA)

	// Account has its own CA — different from the one that issued the leaf cert.
	accountCA := makeCA(t)
	st := &stubDeviceCertStore{
		err: nbstatus.Errorf(nbstatus.NotFound, "not found"),
		trustedCAs: []*types.TrustedCA{
			{PEM: accountCA.certPEM}, // different CA
		},
	}

	err := checkCertRevocation(context.Background(), st, "acct1", "wg-key", leafCert)
	require.Error(t, err)

	st2, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st2.Code())
	assert.Contains(t, st2.Message(), "CA trusted in this account")
}

// TestCheckCertRevocation_ExternalCA_NoAccountCAs_Denied verifies that a cert
// presented when the account has no registered CAs is denied (no trust anchors).
func TestCheckCertRevocation_ExternalCA_NoAccountCAs_Denied(t *testing.T) {
	ca := makeCA(t)
	leafCert := makeLeafCert(t, big.NewInt(7), ca)

	st := &stubDeviceCertStore{
		err:        nbstatus.Errorf(nbstatus.NotFound, "not found"),
		trustedCAs: nil, // no CAs registered for this account
	}

	err := checkCertRevocation(context.Background(), st, "acct1", "wg-key", leafCert)
	require.Error(t, err)

	st2, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st2.Code())
}

// TestCheckCertRevocation_ExternalCA_CAListError_Internal verifies fail-closed behaviour:
// when ListTrustedCAs returns an unexpected error, the check denies access.
func TestCheckCertRevocation_ExternalCA_CAListError_Internal(t *testing.T) {
	ca := makeCA(t)
	leafCert := makeLeafCert(t, big.NewInt(5), ca)

	st := &stubDeviceCertStore{
		err:   nbstatus.Errorf(nbstatus.NotFound, "not found"),
		caErr: nbstatus.Errorf(nbstatus.Internal, "db timeout"),
	}

	err := checkCertRevocation(context.Background(), st, "acct1", "wg-key", leafCert)
	require.Error(t, err)

	st2, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st2.Code())
}

func TestCheckCertRevocation_NotRevoked_Allowed(t *testing.T) {
	serial := big.NewInt(100)
	stored := &types.DeviceCertificate{
		Serial:  serial.String(),
		Revoked: false,
	}
	st := &stubDeviceCertStore{cert: stored}
	cert := selfSignedCert(t, serial)

	err := checkCertRevocation(context.Background(), st, "acct1", "wg-key", cert)
	assert.NoError(t, err)
}

func TestCheckCertRevocation_Revoked_SerialMatch_Denied(t *testing.T) {
	serial := big.NewInt(999)
	now := time.Now().UTC()
	stored := &types.DeviceCertificate{
		Serial:    serial.String(),
		Revoked:   true,
		RevokedAt: &now,
	}
	st := &stubDeviceCertStore{cert: stored}
	cert := selfSignedCert(t, serial)

	err := checkCertRevocation(context.Background(), st, "acct1", "wg-key", cert)
	require.Error(t, err)

	st2, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st2.Code())
	assert.Contains(t, st2.Message(), "revoked")
}

func TestCheckCertRevocation_SerialMismatch_DeniedEvenIfSignedByAccountCA(t *testing.T) {
	// Fail-safe: any serial mismatch is denied regardless of whether the cert was issued
	// by the account CA. Rationale: the peer should always present its current enrolled
	// certificate. A mismatch means either an old (potentially revoked) cert or a cert
	// that was issued outside the normal enrollment flow. In both cases, requiring
	// re-enrollment is the safe outcome. Peers that obtained a cert through normal
	// enrollment always have their current serial stored in the DB.
	ca := makeCA(t)
	storedSerial := big.NewInt(1)
	now := time.Now().UTC()
	stored := &types.DeviceCertificate{
		Serial:    storedSerial.String(),
		Revoked:   true,
		RevokedAt: &now,
	}
	st := &stubDeviceCertStore{
		cert: stored,
		trustedCAs: []*types.TrustedCA{
			{PEM: ca.certPEM},
		},
	}

	presentedCert := makeLeafCert(t, big.NewInt(2), ca) // signed by account CA, different serial
	err := checkCertRevocation(context.Background(), st, "acct1", "wg-key", presentedCert)
	require.Error(t, err, "serial mismatch must be denied even when cert was issued by account CA")
	st2, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st2.Code())
	assert.Contains(t, st2.Message(), "mismatch")
}

func TestCheckCertRevocation_Revoked_SerialMismatch_NotInCA_Denied(t *testing.T) {
	// Stored cert (serial 1) is revoked. Peer presents a cert (serial 2) NOT signed
	// by any account CA. Should be denied: attacker could present an arbitrary cert
	// whose serial happens not to match the stored one.
	storedSerial := big.NewInt(1)
	now := time.Now().UTC()
	stored := &types.DeviceCertificate{
		Serial:    storedSerial.String(),
		Revoked:   true,
		RevokedAt: &now,
	}
	// No trustedCAs configured → verifyCertIssuedByAccountCA will deny.
	st := &stubDeviceCertStore{cert: stored}

	presentedCert := selfSignedCert(t, big.NewInt(2)) // serial mismatch, not in CA pool
	err := checkCertRevocation(context.Background(), st, "acct1", "wg-key", presentedCert)
	require.Error(t, err, "serial mismatch with cert not in account CA pool must be denied")
	st2, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st2.Code())
}
