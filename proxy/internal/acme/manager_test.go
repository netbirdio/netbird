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

func TestHostPolicy(t *testing.T) {
	mgr, err := NewManager(ManagerConfig{CertDir: t.TempDir(), ACMEURL: "https://acme.example.com/directory"}, nil, nil, nil)
	require.NoError(t, err)
	mgr.AddDomain("example.com", "acc1", "rp1")

	// Wait for the background prefetch goroutine to finish so the temp dir
	// can be cleaned up without a race.
	t.Cleanup(func() {
		assert.Eventually(t, func() bool {
			return mgr.PendingCerts() == 0
		}, 30*time.Second, 50*time.Millisecond)
	})

	tests := []struct {
		name    string
		host    string
		wantErr bool
	}{
		{
			name: "exact domain match",
			host: "example.com",
		},
		{
			name: "domain with port",
			host: "example.com:443",
		},
		{
			name:    "unknown domain",
			host:    "unknown.com",
			wantErr: true,
		},
		{
			name:    "unknown domain with port",
			host:    "unknown.com:443",
			wantErr: true,
		},
		{
			name:    "empty host",
			host:    "",
			wantErr: true,
		},
		{
			name:    "port only",
			host:    ":443",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := mgr.hostPolicy(context.Background(), tc.host)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "unknown domain")
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDomainStates(t *testing.T) {
	mgr, err := NewManager(ManagerConfig{CertDir: t.TempDir(), ACMEURL: "https://acme.example.com/directory"}, nil, nil, nil)
	require.NoError(t, err)

	assert.Equal(t, 0, mgr.PendingCerts(), "initially zero")
	assert.Equal(t, 0, mgr.TotalDomains(), "initially zero domains")
	assert.Empty(t, mgr.PendingDomains())
	assert.Empty(t, mgr.ReadyDomains())
	assert.Empty(t, mgr.FailedDomains())

	// AddDomain starts as pending, then the prefetch goroutine will fail
	// (no real ACME server) and transition to failed.
	mgr.AddDomain("a.example.com", "acc1", "rp1")
	mgr.AddDomain("b.example.com", "acc1", "rp1")

	assert.Equal(t, 2, mgr.TotalDomains(), "two domains registered")

	// Pending domains should eventually drain after prefetch goroutines finish.
	assert.Eventually(t, func() bool {
		return mgr.PendingCerts() == 0
	}, 30*time.Second, 100*time.Millisecond, "pending certs should return to zero after prefetch completes")

	assert.Empty(t, mgr.PendingDomains())
	assert.Equal(t, 2, mgr.TotalDomains(), "total domains unchanged")

	// With a fake ACME URL, both should have failed.
	failed := mgr.FailedDomains()
	assert.Len(t, failed, 2, "both domains should have failed")
	assert.Contains(t, failed, "a.example.com")
	assert.Contains(t, failed, "b.example.com")
	assert.Empty(t, mgr.ReadyDomains())
}

func TestParseWildcard(t *testing.T) {
	tests := []struct {
		pattern    string
		wantSuffix string
		wantOK     bool
	}{
		{"*.example.com", ".example.com", true},
		{"*.foo.example.com", ".foo.example.com", true},
		{"*.COM", ".com", false},      // single-label TLD
		{"example.com", "", false},    // no wildcard prefix
		{"*example.com", "", false},   // missing dot
		{"**.example.com", "", false}, // double star
		{"", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.pattern, func(t *testing.T) {
			suffix, ok := parseWildcard(tc.pattern)
			assert.Equal(t, tc.wantOK, ok)
			if ok {
				assert.Equal(t, tc.wantSuffix, suffix)
			}
		})
	}
}

func TestMatchesWildcard(t *testing.T) {
	wcDir := t.TempDir()
	generateSelfSignedCert(t, wcDir, "example", "*.example.com")

	acmeDir := t.TempDir()
	mgr, err := NewManager(ManagerConfig{CertDir: acmeDir, ACMEURL: "https://acme.example.com/directory", WildcardDir: wcDir}, nil, nil, nil)
	require.NoError(t, err)

	tests := []struct {
		host  string
		match bool
	}{
		{"foo.example.com", true},
		{"bar.example.com", true},
		{"FOO.Example.COM", true},      // case insensitive
		{"example.com", false},         // bare parent
		{"sub.foo.example.com", false}, // multi-level
		{"notexample.com", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			assert.Equal(t, tc.match, mgr.matchesWildcard(tc.host))
		})
	}
}

// generateSelfSignedCert creates a temporary self-signed certificate and key
// for testing purposes. The baseName controls the output filenames:
// <baseName>.crt and <baseName>.key.
func generateSelfSignedCert(t *testing.T, dir, baseName string, dnsNames ...string) {
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

	certFile, err := os.Create(filepath.Join(dir, baseName+".crt"))
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	require.NoError(t, certFile.Close())

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyFile, err := os.Create(filepath.Join(dir, baseName+".key"))
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	require.NoError(t, keyFile.Close())
}

func TestWildcardAddDomainSkipsACME(t *testing.T) {
	wcDir := t.TempDir()
	generateSelfSignedCert(t, wcDir, "example", "*.example.com")

	acmeDir := t.TempDir()
	mgr, err := NewManager(ManagerConfig{CertDir: acmeDir, ACMEURL: "https://acme.example.com/directory", WildcardDir: wcDir}, nil, nil, nil)
	require.NoError(t, err)

	// Add a wildcard-matching domain — should be immediately ready.
	mgr.AddDomain("foo.example.com", "acc1", "svc1")
	assert.Equal(t, 0, mgr.PendingCerts(), "wildcard domain should not be pending")
	assert.Equal(t, []string{"foo.example.com"}, mgr.ReadyDomains())

	// Add a non-wildcard domain — should go through ACME (pending then failed).
	mgr.AddDomain("other.net", "acc2", "svc2")
	assert.Equal(t, 2, mgr.TotalDomains())

	// Wait for the ACME prefetch to fail.
	assert.Eventually(t, func() bool {
		return mgr.PendingCerts() == 0
	}, 30*time.Second, 100*time.Millisecond)

	assert.Equal(t, []string{"foo.example.com"}, mgr.ReadyDomains())
	assert.Contains(t, mgr.FailedDomains(), "other.net")
}

func TestWildcardGetCertificate(t *testing.T) {
	wcDir := t.TempDir()
	generateSelfSignedCert(t, wcDir, "example", "*.example.com")

	acmeDir := t.TempDir()
	mgr, err := NewManager(ManagerConfig{CertDir: acmeDir, ACMEURL: "https://acme.example.com/directory", WildcardDir: wcDir}, nil, nil, nil)
	require.NoError(t, err)

	mgr.AddDomain("foo.example.com", "acc1", "svc1")

	// GetCertificate for a wildcard-matching domain should return the static cert.
	cert, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "foo.example.com"})
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.Contains(t, cert.Leaf.DNSNames, "*.example.com")
}

func TestMultipleWildcards(t *testing.T) {
	wcDir := t.TempDir()
	generateSelfSignedCert(t, wcDir, "example", "*.example.com")
	generateSelfSignedCert(t, wcDir, "other", "*.other.org")

	acmeDir := t.TempDir()
	mgr, err := NewManager(ManagerConfig{CertDir: acmeDir, ACMEURL: "https://acme.example.com/directory", WildcardDir: wcDir}, nil, nil, nil)
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"*.example.com", "*.other.org"}, mgr.WildcardPatterns())

	// Both wildcards should resolve.
	mgr.AddDomain("foo.example.com", "acc1", "svc1")
	mgr.AddDomain("bar.other.org", "acc2", "svc2")

	assert.Equal(t, 0, mgr.PendingCerts())
	assert.ElementsMatch(t, []string{"foo.example.com", "bar.other.org"}, mgr.ReadyDomains())

	// GetCertificate routes to the correct cert.
	cert1, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "foo.example.com"})
	require.NoError(t, err)
	assert.Contains(t, cert1.Leaf.DNSNames, "*.example.com")

	cert2, err := mgr.GetCertificate(&tls.ClientHelloInfo{ServerName: "bar.other.org"})
	require.NoError(t, err)
	assert.Contains(t, cert2.Leaf.DNSNames, "*.other.org")

	// Non-matching domain falls through to ACME.
	mgr.AddDomain("custom.net", "acc3", "svc3")
	assert.Eventually(t, func() bool {
		return mgr.PendingCerts() == 0
	}, 30*time.Second, 100*time.Millisecond)
	assert.Contains(t, mgr.FailedDomains(), "custom.net")
}

func TestWildcardDirEmpty(t *testing.T) {
	wcDir := t.TempDir()
	// Empty directory — no .crt files.
	_, err := NewManager(ManagerConfig{CertDir: t.TempDir(), ACMEURL: "https://acme.example.com/directory", WildcardDir: wcDir}, nil, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no .crt files found")
}

func TestWildcardDirNonWildcardCert(t *testing.T) {
	wcDir := t.TempDir()
	// Certificate without a wildcard SAN.
	generateSelfSignedCert(t, wcDir, "plain", "plain.example.com")

	_, err := NewManager(ManagerConfig{CertDir: t.TempDir(), ACMEURL: "https://acme.example.com/directory", WildcardDir: wcDir}, nil, nil, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no wildcard SANs")
}

func TestNoWildcardDir(t *testing.T) {
	// Empty string means no wildcard dir — pure ACME mode.
	mgr, err := NewManager(ManagerConfig{CertDir: t.TempDir(), ACMEURL: "https://acme.example.com/directory"}, nil, nil, nil)
	require.NoError(t, err)
	assert.Empty(t, mgr.WildcardPatterns())
}
