package cert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateKey(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	require.NoError(t, err)

	key, err := mgr.GenerateKey()
	require.NoError(t, err)
	require.NotNil(t, key)

	ecKey, ok := key.(*ecdsa.PrivateKey)
	require.True(t, ok, "expected ECDSA key")
	assert.Equal(t, elliptic.P256(), ecKey.Curve)
}

func TestCreateCSR(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	require.NoError(t, err)

	key, err := mgr.GenerateKey()
	require.NoError(t, err)

	csrDER, err := mgr.CreateCSR(key, "peer1.netbird.example", false)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	assert.Equal(t, "peer1.netbird.example", csr.Subject.CommonName)
	assert.Equal(t, []string{"peer1.netbird.example"}, csr.DNSNames)
}

func TestCreateCSRWildcard(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	require.NoError(t, err)

	key, err := mgr.GenerateKey()
	require.NoError(t, err)

	csrDER, err := mgr.CreateCSR(key, "peer1.netbird.example", true)
	require.NoError(t, err)

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	assert.Equal(t, "peer1.netbird.example", csr.Subject.CommonName)
	assert.Contains(t, csr.DNSNames, "peer1.netbird.example")
	assert.Contains(t, csr.DNSNames, "*.peer1.netbird.example")
	assert.Len(t, csr.DNSNames, 2)
}

func TestStoreCertAndLoad(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	require.NoError(t, err)

	certPEM, keyPEM := generateTestCert(t, "test.netbird.example", time.Now().Add(365*24*time.Hour))

	err = mgr.StoreCert(certPEM, []byte("chain"), keyPEM)
	require.NoError(t, err)

	loaded, err := mgr.LoadCert()
	require.NoError(t, err)
	assert.Equal(t, "test.netbird.example", loaded.Subject.CommonName)
	assert.Contains(t, loaded.DNSNames, "test.netbird.example")
}

func TestStoreCA(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	require.NoError(t, err)

	ca1 := []byte("-----BEGIN CERTIFICATE-----\nCA1\n-----END CERTIFICATE-----\n")
	ca2 := []byte("-----BEGIN CERTIFICATE-----\nCA2\n-----END CERTIFICATE-----\n")

	err = mgr.StoreCA([][]byte{ca1, ca2})
	require.NoError(t, err)

	data, err := os.ReadFile(mgr.CAPath())
	require.NoError(t, err)
	assert.Contains(t, string(data), "CA1")
	assert.Contains(t, string(data), "CA2")
}

func TestHasCert(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	require.NoError(t, err)

	assert.False(t, mgr.HasCert())

	certPEM, keyPEM := generateTestCert(t, "test.example", time.Now().Add(365*24*time.Hour))
	err = mgr.StoreCert(certPEM, []byte("chain"), keyPEM)
	require.NoError(t, err)

	assert.True(t, mgr.HasCert())
}

func TestNeedsRenewal(t *testing.T) {
	t.Run("expiring soon", func(t *testing.T) {
		mgr, err := NewManager(t.TempDir())
		require.NoError(t, err)

		certPEM, keyPEM := generateTestCert(t, "test.example", time.Now().Add(10*24*time.Hour))
		err = mgr.StoreCert(certPEM, []byte("chain"), keyPEM)
		require.NoError(t, err)

		assert.True(t, mgr.NeedsRenewal(30*24*time.Hour))
	})

	t.Run("not expiring soon", func(t *testing.T) {
		mgr, err := NewManager(t.TempDir())
		require.NoError(t, err)

		certPEM, keyPEM := generateTestCert(t, "test.example", time.Now().Add(365*24*time.Hour))
		err = mgr.StoreCert(certPEM, []byte("chain"), keyPEM)
		require.NoError(t, err)

		assert.False(t, mgr.NeedsRenewal(30*24*time.Hour))
	})

	t.Run("no cert returns true", func(t *testing.T) {
		mgr, err := NewManager(t.TempDir())
		require.NoError(t, err)

		assert.True(t, mgr.NeedsRenewal(30*24*time.Hour))
	})
}

func TestFQDNChanged(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	require.NoError(t, err)

	certPEM, keyPEM := generateTestCert(t, "old.netbird.example", time.Now().Add(365*24*time.Hour))
	err = mgr.StoreCert(certPEM, []byte("chain"), keyPEM)
	require.NoError(t, err)

	assert.False(t, mgr.FQDNChanged("old.netbird.example"))
	assert.True(t, mgr.FQDNChanged("new.netbird.example"))
}

func TestFQDNChangedNoCert(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	require.NoError(t, err)

	assert.False(t, mgr.FQDNChanged("any.example"))
}

func TestKeyFilePermissions(t *testing.T) {
	mgr, err := NewManager(t.TempDir())
	require.NoError(t, err)

	certPEM, keyPEM := generateTestCert(t, "test.example", time.Now().Add(365*24*time.Hour))
	err = mgr.StoreCert(certPEM, []byte("chain"), keyPEM)
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(mgr.certDir, keyFileName))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestPaths(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewManager(dir)
	require.NoError(t, err)

	assert.Equal(t, filepath.Join(dir, "cert.pem"), mgr.CertPath())
	assert.Equal(t, filepath.Join(dir, "key.pem"), mgr.KeyPath())
	assert.Equal(t, filepath.Join(dir, "chain.pem"), mgr.ChainPath())
	assert.Equal(t, filepath.Join(dir, "ca.pem"), mgr.CAPath())
}

// generateTestCert creates a self-signed certificate with the given FQDN and expiry.
func generateTestCert(t *testing.T, fqdn string, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: fqdn},
		DNSNames:     []string{fqdn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}
