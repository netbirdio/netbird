package proxy

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

	"github.com/netbirdio/netbird/proxy/internal/certwatch"
	"github.com/netbirdio/netbird/shared/management/domain"
)

func generateCertWithSANs(t *testing.T, dnsNames []string) (certPEM, keyPEM []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: dnsNames[0]},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

func newStaticWatcher(t *testing.T, dnsNames []string) *certwatch.Watcher {
	t.Helper()

	dir := t.TempDir()
	certPEM, keyPEM := generateCertWithSANs(t, dnsNames)
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	w, err := certwatch.NewWatcher(certPath, keyPath, quietLifecycleLogger())
	require.NoError(t, err)
	return w
}

func TestStaticCertCovers(t *testing.T) {
	s := &Server{
		Logger:            quietLifecycleLogger(),
		staticCertWatcher: newStaticWatcher(t, []string{"*.p.example.com", "exact.example.com"}),
	}

	cases := []struct {
		domain  string
		covered bool
	}{
		{"svc.p.example.com", true},
		{"exact.example.com", true},
		{"a.b.p.example.com", false}, // wildcard does not span labels
		{"p.example.com", false},
		{"other.example.com", false},
	}
	for _, tc := range cases {
		t.Run(tc.domain, func(t *testing.T) {
			assert.Equal(t, tc.covered, s.staticCertCovers(domain.Domain(tc.domain)))
		})
	}
}

func TestStaticCertCoversNoWatcher(t *testing.T) {
	s := &Server{Logger: quietLifecycleLogger()}
	assert.False(t, s.staticCertCovers(domain.Domain("svc.p.example.com")))
}
