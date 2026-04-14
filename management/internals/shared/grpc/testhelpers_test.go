package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/account"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// ─── Minimal account.Manager stub for attestation tests ───────────────────────

// testAccountManager implements only the subset of account.Manager needed by
// the attestation handlers. All other methods are provided by the embedded
// interface (nil zero-value) and will panic if unexpectedly called.
type testAccountManager struct {
	account.Manager
	accountID string
	settings  *types.Settings
	st        store.Store
}

func (m *testAccountManager) GetAccountIDForPeerKey(_ context.Context, _ string) (string, error) {
	return m.accountID, nil
}

func (m *testAccountManager) GetAccountSettings(_ context.Context, _, _ string) (*types.Settings, error) {
	return m.settings, nil
}

func (m *testAccountManager) GetStore() store.Store {
	return m.st
}

// ─── Minimal store.Store stub for attestation tests ───────────────────────────

// testAttestationStore implements the store.Store methods called during
// attestation cert issuance. All other methods panic if called.
type testAttestationStore struct {
	store.Store
}

func (s *testAttestationStore) ListTrustedCAs(_ context.Context, _ store.LockingStrength, _ string) ([]*types.TrustedCA, error) {
	return nil, nil // no CA persisted → newBuiltinCA will create a fresh in-memory one
}

func (s *testAttestationStore) SaveTrustedCA(_ context.Context, _ store.LockingStrength, _ *types.TrustedCA) error {
	return nil
}

func (s *testAttestationStore) GetPeerByPeerPubKey(_ context.Context, _ store.LockingStrength, _ string) (*nbpeer.Peer, error) {
	return nil, nil // no peer record; peerID will be "" — valid for cert issuance
}

func (s *testAttestationStore) SaveDeviceCertificate(_ context.Context, _ store.LockingStrength, _ *types.DeviceCertificate) error {
	return nil
}

func (s *testAttestationStore) SaveEnrollmentRequest(_ context.Context, _ store.LockingStrength, _ *types.EnrollmentRequest) error {
	return nil
}

// buildCSRPEM generates a valid PKCS#10 CSR with CommonName "test-peer".
func buildCSRPEM(t *testing.T) string {
	t.Helper()
	return buildCSRPEMWithCN(t, "test-peer")
}

// buildCSRPEMWithCN generates a valid PKCS#10 CSR with the given CommonName.
func buildCSRPEMWithCN(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// buildCSRPEMWithKey generates a PKCS#10 CSR using the supplied key.
// The CommonName is set to "test-peer". Use this when the CSR public key must
// match a separately-created certificate (e.g. Apple SE attestation tests).
func buildCSRPEMWithKey(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test-peer"}}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// buildSelfSignedCertPEM generates a self-signed ECC certificate and returns its PEM encoding.
func buildSelfSignedCertPEM(t *testing.T) (certPEM string, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), key
}

// buildPublicKeyPEM encodes an ECDSA public key as PKIX PEM.
func buildPublicKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// generateRSAKeyForTest generates an RSA-2048 public key and returns its PKIX PEM encoding.
func generateRSAKeyForTest(t *testing.T) (string, error) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})), nil
}

// testChain holds a 3-tier certificate chain: root → intermediate → leaf.
type testChain struct {
	RootPEM         string
	IntermediatePEM string
	LeafPEM         string
	LeafKey         *ecdsa.PrivateKey
	// RootCert is the parsed root certificate; needed to build the root pool.
	RootCert *x509.Certificate
}

// buildTestCertChain creates a root CA, an intermediate CA signed by the root, and a
// leaf certificate signed by the intermediate. The leaf key is freshly generated.
// Use this to test Apple SE attestation chain verification without hitting Apple servers.
func buildTestCertChain(t *testing.T) testChain {
	t.Helper()

	// Root CA (self-signed)
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	rootCert, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}))

	// Intermediate CA (signed by root)
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	interDER, err := x509.CreateCertificate(rand.Reader, interTmpl, rootCert, &interKey.PublicKey, rootKey)
	require.NoError(t, err)
	interCert, err := x509.ParseCertificate(interDER)
	require.NoError(t, err)
	intermediatePEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER}))

	// Leaf cert (signed by intermediate)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, interCert, &leafKey.PublicKey, interKey)
	require.NoError(t, err)
	leafPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))

	return testChain{
		RootPEM:         rootPEM,
		IntermediatePEM: intermediatePEM,
		LeafPEM:         leafPEM,
		LeafKey:         leafKey,
		RootCert:        rootCert,
	}
}
