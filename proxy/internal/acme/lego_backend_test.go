package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/tls"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// validLegoCfg returns a config with all required fields populated.
// Tests can mutate one field to exercise validation.
func validLegoCfg(t *testing.T) LegoBackendConfig {
	t.Helper()
	return LegoBackendConfig{
		CertDir:          t.TempDir(),
		ACMEDirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory",
		AccountEmail:     "ops@example.com",
		DNSProvider:      "cloudflare",
		DNSCredentials:   "fake-token-not-used-because-cache-hit",
	}
}

func TestNewLegoBackendValidation(t *testing.T) {
	cases := []struct {
		name        string
		mutate      func(*LegoBackendConfig)
		errContains string
	}{
		{"empty CertDir", func(c *LegoBackendConfig) { c.CertDir = "" }, "cert dir"},
		{"empty ACMEDirectoryURL", func(c *LegoBackendConfig) { c.ACMEDirectoryURL = "" }, "ACME directory URL"},
		{"empty AccountEmail", func(c *LegoBackendConfig) { c.AccountEmail = "" }, "account email"},
		{"empty DNSProvider", func(c *LegoBackendConfig) { c.DNSProvider = "" }, "DNS provider"},
		{"empty DNSCredentials", func(c *LegoBackendConfig) { c.DNSCredentials = "" }, "DNS credentials"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validLegoCfg(t)
			tc.mutate(&cfg)
			_, err := NewLegoBackend(cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errContains)
		})
	}
}

func TestNewLegoBackendCreatesStorageDir(t *testing.T) {
	cfg := validLegoCfg(t)
	_, err := NewLegoBackend(cfg)
	require.NoError(t, err)

	storage := filepath.Join(cfg.CertDir, "lego")
	info, err := os.Stat(storage)
	require.NoError(t, err)
	assert.True(t, info.IsDir(), "storage subdir should be a directory")
}

func TestLegoBackendGetCertificateCacheHit(t *testing.T) {
	cfg := validLegoCfg(t)
	backend, err := NewLegoBackend(cfg)
	require.NoError(t, err)

	const host = "private.example.com"
	storage := filepath.Join(cfg.CertDir, "lego")
	writeTestCertPair(t, storage, host)

	// GetCertificate must hit the cache and return the cert without
	// invoking Lego (which would fail because the token is fake and the
	// ACME URL points at staging — neither is reachable from this test).
	cert, err := backend.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
	require.NoError(t, err)
	require.NotNil(t, cert)
	require.NotNil(t, cert.Leaf)
	assert.Contains(t, cert.Leaf.DNSNames, host)
}

func TestLegoBackendGetCertificateMissingSNI(t *testing.T) {
	backend, err := NewLegoBackend(validLegoCfg(t))
	require.NoError(t, err)

	_, err = backend.GetCertificate(&tls.ClientHelloInfo{ServerName: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "SNI")
}

func TestLegoBackendReadCertFromDiskHit(t *testing.T) {
	cfg := validLegoCfg(t)
	backend, err := NewLegoBackend(cfg)
	require.NoError(t, err)

	const host = "internal.example.com"
	storage := filepath.Join(cfg.CertDir, "lego")
	writeTestCertPair(t, storage, host)

	cert, err := backend.ReadCertFromDisk(context.Background(), host)
	require.NoError(t, err)
	require.NotNil(t, cert)
	require.NotNil(t, cert.Leaf)
	assert.Contains(t, cert.Leaf.DNSNames, host)
}

func TestLegoBackendReadCertFromDiskMiss(t *testing.T) {
	backend, err := NewLegoBackend(validLegoCfg(t))
	require.NoError(t, err)

	_, err = backend.ReadCertFromDisk(context.Background(), "absent.example.com")
	require.Error(t, err)
}

func TestLegoBackendDeleteCert(t *testing.T) {
	cfg := validLegoCfg(t)
	backend, err := NewLegoBackend(cfg)
	require.NoError(t, err)

	const host = "ephemeral.example.com"
	storage := filepath.Join(cfg.CertDir, "lego")
	writeTestCertPair(t, storage, host)

	// Pre-deletion: files exist.
	require.FileExists(t, filepath.Join(storage, host+".crt"))
	require.FileExists(t, filepath.Join(storage, host+".key"))

	require.NoError(t, backend.DeleteCert(context.Background(), host))
	assert.NoFileExists(t, filepath.Join(storage, host+".crt"))
	assert.NoFileExists(t, filepath.Join(storage, host+".key"))

	// Idempotent: deleting again is not an error.
	assert.NoError(t, backend.DeleteCert(context.Background(), host))
}

// writeTestCertPair writes a self-signed leaf certificate plus its
// private key to <dir>/<host>.crt and <dir>/<host>.key. The cert is
// short-lived but valid for the next 24 hours, which is enough for the
// LegoBackend's cache-hit path to accept it.
func writeTestCertPair(t *testing.T, dir, host string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     []string{host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPath := filepath.Join(dir, host+".crt")
	certFile, err := os.Create(certPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	require.NoError(t, certFile.Close())

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPath := filepath.Join(dir, host+".key")
	keyFile, err := os.Create(keyPath)
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	require.NoError(t, keyFile.Close())
}
