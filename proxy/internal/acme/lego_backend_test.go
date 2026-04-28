package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
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

// validLegoCfg returns a config with all required fields populated.
// Tests can mutate one field to exercise validation.
func validLegoCfg(t *testing.T) LegoBackendConfig {
	t.Helper()
	return LegoBackendConfig{
		CertDir: t.TempDir(),
	}
}

func TestNewLegoBackendValidation(t *testing.T) {
	cfg := LegoBackendConfig{} // empty CertDir
	_, err := NewLegoBackend(cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cert dir")
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

	// GetCertificate must hit the cache and return the cert. After
	// Slice B, GetCertificate never invokes Lego — issuance is
	// exclusively via Issue() called from the manager's prefetch path.
	cert, err := backend.GetCertificate(&tls.ClientHelloInfo{ServerName: host})
	require.NoError(t, err)
	require.NotNil(t, cert)
	require.NotNil(t, cert.Leaf)
	assert.Contains(t, cert.Leaf.DNSNames, host)
}

func TestLegoBackendGetCertificateMissReturnsError(t *testing.T) {
	backend, err := NewLegoBackend(validLegoCfg(t))
	require.NoError(t, err)

	_, err = backend.GetCertificate(&tls.ClientHelloInfo{ServerName: "uncached.example.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no cached lego cert")
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

	require.FileExists(t, filepath.Join(storage, host+".crt"))
	require.FileExists(t, filepath.Join(storage, host+".key"))

	require.NoError(t, backend.DeleteCert(context.Background(), host))
	assert.NoFileExists(t, filepath.Join(storage, host+".crt"))
	assert.NoFileExists(t, filepath.Join(storage, host+".key"))

	// Idempotent.
	assert.NoError(t, backend.DeleteCert(context.Background(), host))
}

func TestLegoBackendIssueValidation(t *testing.T) {
	backend, err := NewLegoBackend(validLegoCfg(t))
	require.NoError(t, err)

	cases := []struct {
		name                                                   string
		domain, provider, email, acmeURL, secret, errSubstring string
	}{
		{"empty domain", "", "cloudflare", "ops@example.com", "https://acme.example/dir", "tok", "domain is required"},
		{"empty provider", "x.example.com", "", "ops@example.com", "https://acme.example/dir", "tok", "provider name is required"},
		{"empty email", "x.example.com", "cloudflare", "", "https://acme.example/dir", "tok", "account email is required"},
		{"empty acme URL", "x.example.com", "cloudflare", "ops@example.com", "", "tok", "ACME directory URL is required"},
		{"empty secret", "x.example.com", "cloudflare", "ops@example.com", "https://acme.example/dir", "", "plaintext secret is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := backend.Issue(context.Background(), tc.domain, tc.provider, tc.email, tc.acmeURL, tc.secret)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errSubstring)
		})
	}
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
