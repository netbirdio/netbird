package inspect

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert, key
}

func TestCertProvider_GetCertificate(t *testing.T) {
	ca, caKey := generateTestCA(t)
	provider := NewCertProvider(ca, caKey)

	cert, err := provider.GetCertificate("example.com")
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Verify the leaf certificate
	assert.Equal(t, "example.com", cert.Leaf.Subject.CommonName)
	assert.Contains(t, cert.Leaf.DNSNames, "example.com")

	// Verify chain: leaf + CA
	assert.Len(t, cert.Certificate, 2)

	// Verify leaf is signed by our CA
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	_, err = cert.Leaf.Verify(x509.VerifyOptions{
		Roots: pool,
	})
	require.NoError(t, err)
}

func TestCertProvider_CachesResults(t *testing.T) {
	ca, caKey := generateTestCA(t)
	provider := NewCertProvider(ca, caKey)

	cert1, err := provider.GetCertificate("cached.example.com")
	require.NoError(t, err)

	cert2, err := provider.GetCertificate("cached.example.com")
	require.NoError(t, err)

	// Same pointer = cached
	assert.Equal(t, cert1, cert2)
}

func TestCertProvider_DifferentHostsDifferentCerts(t *testing.T) {
	ca, caKey := generateTestCA(t)
	provider := NewCertProvider(ca, caKey)

	cert1, err := provider.GetCertificate("a.example.com")
	require.NoError(t, err)

	cert2, err := provider.GetCertificate("b.example.com")
	require.NoError(t, err)

	assert.NotEqual(t, cert1.Leaf.SerialNumber, cert2.Leaf.SerialNumber)
}

func TestCertProvider_TLSConfigHandshake(t *testing.T) {
	ca, caKey := generateTestCA(t)
	provider := NewCertProvider(ca, caKey)

	tlsConfig := provider.GetTLSConfig()
	require.NotNil(t, tlsConfig)
	require.NotNil(t, tlsConfig.GetCertificate)

	// Simulate a ClientHelloInfo
	hello := &tls.ClientHelloInfo{
		ServerName: "handshake.example.com",
	}

	cert, err := tlsConfig.GetCertificate(hello)
	require.NoError(t, err)
	assert.Equal(t, "handshake.example.com", cert.Leaf.Subject.CommonName)
}

func TestCertCache_Eviction(t *testing.T) {
	cache := newCertCache(3)

	for i := range 5 {
		hostname := string(rune('a'+i)) + ".example.com"
		cache.put(hostname, &tls.Certificate{})
	}

	// Only 3 should remain (c, d, e - the most recent)
	assert.Len(t, cache.entries, 3)

	_, ok := cache.get("a.example.com")
	assert.False(t, ok, "oldest entry should be evicted")

	_, ok = cache.get("b.example.com")
	assert.False(t, ok, "second oldest should be evicted")

	_, ok = cache.get("e.example.com")
	assert.True(t, ok, "newest entry should exist")
}
