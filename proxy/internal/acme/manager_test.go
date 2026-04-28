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
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/domain"
)

// newTestManager builds a Manager backed by an autocert backend pointed at a
// fake ACME directory URL. Used in tests to verify behavior without real
// cert issuance — issuance attempts fail predictably against the fake URL.
func newTestManager(t *testing.T, cfg ManagerConfig, acmeURL string) (*Manager, error) {
	t.Helper()
	backend, err := NewAutocertBackend(AutocertBackendConfig{
		CertDir: cfg.CertDir,
		ACMEURL: acmeURL,
	})
	if err != nil {
		return nil, err
	}
	backends := map[string]CertBackend{
		"tls-alpn-01": backend,
		"http-01":     backend,
	}
	return NewManager(cfg, backends, "tls-alpn-01", nil, nil, nil)
}

// addTestDomain calls AddDomain with empty options and asserts no error,
// matching the pre-Slice-B test ergonomics. Tests that need to verify
// the per-service options or error path call AddDomain directly.
func addTestDomain(t *testing.T, mgr *Manager, d domain.Domain, accountID types.AccountID, serviceID types.ServiceID) bool {
	t.Helper()
	wildcardHit, err := mgr.AddDomain(d, accountID, serviceID, AddDomainOptions{})
	require.NoError(t, err)
	return wildcardHit
}

func TestHostPolicy(t *testing.T) {
	mgr, err := newTestManager(t, ManagerConfig{CertDir: t.TempDir()}, "https://acme.example.com/directory")
	require.NoError(t, err)
	addTestDomain(t, mgr, "example.com", types.AccountID("acc1"), types.ServiceID("rp1"))

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
	mgr, err := newTestManager(t, ManagerConfig{CertDir: t.TempDir()}, "https://acme.example.com/directory")
	require.NoError(t, err)

	assert.Equal(t, 0, mgr.PendingCerts(), "initially zero")
	assert.Equal(t, 0, mgr.TotalDomains(), "initially zero domains")
	assert.Empty(t, mgr.PendingDomains())
	assert.Empty(t, mgr.ReadyDomains())
	assert.Empty(t, mgr.FailedDomains())

	// AddDomain starts as pending, then the prefetch goroutine will fail
	// (no real ACME server) and transition to failed.
	addTestDomain(t, mgr, "a.example.com", types.AccountID("acc1"), types.ServiceID("rp1"))
	addTestDomain(t, mgr, "b.example.com", types.AccountID("acc1"), types.ServiceID("rp1"))

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
		{"*.COM", ".com", true},       // single-label TLD
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
	mgr, err := newTestManager(t, ManagerConfig{CertDir: acmeDir, WildcardDir: wcDir}, "https://acme.example.com/directory")
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
			assert.Equal(t, tc.match, mgr.findWildcardEntry(tc.host) != nil)
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
	mgr, err := newTestManager(t, ManagerConfig{CertDir: acmeDir, WildcardDir: wcDir}, "https://acme.example.com/directory")
	require.NoError(t, err)

	// Add a wildcard-matching domain — should be immediately ready.
	addTestDomain(t, mgr, "foo.example.com", types.AccountID("acc1"), types.ServiceID("svc1"))
	assert.Equal(t, 0, mgr.PendingCerts(), "wildcard domain should not be pending")
	assert.Equal(t, []string{"foo.example.com"}, mgr.ReadyDomains())

	// Add a non-wildcard domain — should go through ACME (pending then failed).
	addTestDomain(t, mgr, "other.net", types.AccountID("acc2"), types.ServiceID("svc2"))
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
	mgr, err := newTestManager(t, ManagerConfig{CertDir: acmeDir, WildcardDir: wcDir}, "https://acme.example.com/directory")
	require.NoError(t, err)

	addTestDomain(t, mgr, "foo.example.com", types.AccountID("acc1"), types.ServiceID("svc1"))

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
	mgr, err := newTestManager(t, ManagerConfig{CertDir: acmeDir, WildcardDir: wcDir}, "https://acme.example.com/directory")
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"*.example.com", "*.other.org"}, mgr.WildcardPatterns())

	// Both wildcards should resolve.
	addTestDomain(t, mgr, "foo.example.com", types.AccountID("acc1"), types.ServiceID("svc1"))
	addTestDomain(t, mgr, "bar.other.org", types.AccountID("acc2"), types.ServiceID("svc2"))

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
	addTestDomain(t, mgr, "custom.net", types.AccountID("acc3"), types.ServiceID("svc3"))
	assert.Eventually(t, func() bool {
		return mgr.PendingCerts() == 0
	}, 30*time.Second, 100*time.Millisecond)
	assert.Contains(t, mgr.FailedDomains(), "custom.net")
}

func TestWildcardDirEmpty(t *testing.T) {
	wcDir := t.TempDir()
	// Empty directory — no .crt files.
	_, err := newTestManager(t, ManagerConfig{CertDir: t.TempDir(), WildcardDir: wcDir}, "https://acme.example.com/directory")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no .crt files found")
}

func TestWildcardDirNonWildcardCert(t *testing.T) {
	wcDir := t.TempDir()
	// Certificate without a wildcard SAN.
	generateSelfSignedCert(t, wcDir, "plain", "plain.example.com")

	_, err := newTestManager(t, ManagerConfig{CertDir: t.TempDir(), WildcardDir: wcDir}, "https://acme.example.com/directory")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no wildcard SANs")
}

func TestNoWildcardDir(t *testing.T) {
	// Empty string means no wildcard dir — pure ACME mode.
	mgr, err := newTestManager(t, ManagerConfig{CertDir: t.TempDir()}, "https://acme.example.com/directory")
	require.NoError(t, err)
	assert.Empty(t, mgr.WildcardPatterns())
}

// countingBackend is a CertBackend test double. It counts GetCertificate
// invocations and remembers each issued cert so subsequent ReadCertFromDisk
// calls return them — modeling the cross-replica disk-cache short circuit
// that lets a second goroutine skip re-issuance.
type countingBackend struct {
	mu           sync.Mutex
	issuedCount  int
	deletedCount int
	issued       map[string]*tls.Certificate
	deleted      []string
	issueDelay   time.Duration
}

func newCountingBackend(issueDelay time.Duration) *countingBackend {
	return &countingBackend{
		issued:     make(map[string]*tls.Certificate),
		issueDelay: issueDelay,
	}
}

func (b *countingBackend) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if b.issueDelay > 0 {
		time.Sleep(b.issueDelay)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.issuedCount++
	cert := &tls.Certificate{}
	b.issued[hello.ServerName] = cert
	return cert, nil
}

func (b *countingBackend) ReadCertFromDisk(_ context.Context, name string) (*tls.Certificate, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cert, ok := b.issued[name]; ok {
		return cert, nil
	}
	return nil, errors.New("not issued yet")
}

func (b *countingBackend) DeleteCert(_ context.Context, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.deletedCount++
	b.deleted = append(b.deleted, name)
	delete(b.issued, name)
	return nil
}

func (b *countingBackend) IssuedCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.issuedCount
}

func (b *countingBackend) DeletedCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.deletedCount
}

func (b *countingBackend) DeletedNames() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, len(b.deleted))
	copy(out, b.deleted)
	return out
}

// TestPrefetchSerializesIssuance verifies that two concurrent AddDomain
// calls for the same domain result in only one backend issuance: the
// distributed lock serializes the prefetch goroutines, and the second one
// finds the cert via ReadCertFromDisk after the first one writes it. This
// is the core cross-replica safety property the orchestrator owes to its
// backend — Wave 2's LegoBackend will rely on the same contract.
func TestPrefetchSerializesIssuance(t *testing.T) {
	backend := newCountingBackend(50 * time.Millisecond)

	backends := map[string]CertBackend{"tls-alpn-01": backend}
	mgr, err := NewManager(ManagerConfig{CertDir: t.TempDir()}, backends, "tls-alpn-01", nil, nil, nil)
	require.NoError(t, err)

	const dom = "example.com"
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = mgr.AddDomain(dom, types.AccountID("a"), types.ServiceID("s1"), AddDomainOptions{})
	}()
	go func() {
		defer wg.Done()
		_, _ = mgr.AddDomain(dom, types.AccountID("a"), types.ServiceID("s2"), AddDomainOptions{})
	}()
	wg.Wait()

	require.Eventually(t, func() bool {
		return mgr.PendingCerts() == 0
	}, 10*time.Second, 50*time.Millisecond, "prefetch goroutines should drain")

	assert.Equal(t, 1, backend.IssuedCount(),
		"two AddDomain calls for the same domain should result in only one backend issuance via the locker + ReadCertFromDisk short circuit")
	assert.Contains(t, mgr.ReadyDomains(), dom)
}

// drainPrefetch waits until all prefetch goroutines have finished. Tests
// that exercise AddDomain need this so backend counters stabilize before
// assertions run.
func drainPrefetch(t *testing.T, mgr *Manager) {
	t.Helper()
	require.Eventually(t, func() bool {
		return mgr.PendingCerts() == 0
	}, 10*time.Second, 50*time.Millisecond, "prefetch goroutines should drain")
}

// TestPerServiceBackendRouting verifies that AddDomain with different
// per-service ChallengeType values routes each domain to the matching
// backend.
func TestPerServiceBackendRouting(t *testing.T) {
	tlsBackend := newCountingBackend(0)
	dnsBackend := newCountingBackend(0)
	backends := map[string]CertBackend{
		"tls-alpn-01": tlsBackend,
		"dns-01":      dnsBackend,
	}
	mgr, err := NewManager(ManagerConfig{CertDir: t.TempDir()}, backends, "tls-alpn-01", nil, nil, nil)
	require.NoError(t, err)

	_, err = mgr.AddDomain("public.example.com", types.AccountID("acc"), types.ServiceID("svc1"), AddDomainOptions{ChallengeType: "tls-alpn-01"})
	require.NoError(t, err)
	_, err = mgr.AddDomain("private.example.com", types.AccountID("acc"), types.ServiceID("svc2"), AddDomainOptions{ChallengeType: "dns-01"})
	require.NoError(t, err)
	drainPrefetch(t, mgr)

	assert.Equal(t, 1, tlsBackend.IssuedCount(), "public service should issue via tls-alpn-01 backend")
	assert.Equal(t, 1, dnsBackend.IssuedCount(), "private service should issue via dns-01 backend")
}

// TestAddDomainEmptyChallengeTypeUsesDefault confirms backwards compat:
// a service with no per-service ChallengeType falls back to the manager's
// default backend.
func TestAddDomainEmptyChallengeTypeUsesDefault(t *testing.T) {
	tlsBackend := newCountingBackend(0)
	dnsBackend := newCountingBackend(0)
	backends := map[string]CertBackend{
		"tls-alpn-01": tlsBackend,
		"dns-01":      dnsBackend,
	}
	mgr, err := NewManager(ManagerConfig{CertDir: t.TempDir()}, backends, "tls-alpn-01", nil, nil, nil)
	require.NoError(t, err)

	_, err = mgr.AddDomain("legacy.example.com", types.AccountID("acc"), types.ServiceID("svc"), AddDomainOptions{})
	require.NoError(t, err)
	drainPrefetch(t, mgr)

	assert.Equal(t, 1, tlsBackend.IssuedCount(), "empty ChallengeType should use default backend")
	assert.Equal(t, 0, dnsBackend.IssuedCount(), "non-default backend should not have been touched")
}

// TestAddDomainUnknownChallengeTypeErrors verifies that requesting a
// challenge type with no registered backend produces a clear error.
func TestAddDomainUnknownChallengeTypeErrors(t *testing.T) {
	backend := newCountingBackend(0)
	backends := map[string]CertBackend{"tls-alpn-01": backend}
	mgr, err := NewManager(ManagerConfig{CertDir: t.TempDir()}, backends, "tls-alpn-01", nil, nil, nil)
	require.NoError(t, err)

	_, err = mgr.AddDomain("anywhere.example.com", types.AccountID("acc"), types.ServiceID("svc"), AddDomainOptions{ChallengeType: "dns-01"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no backend registered for challenge type")
	assert.Equal(t, 0, backend.IssuedCount(), "no backend should have been invoked")
}

// TestConversionDeletesOldCert verifies that flipping a service's
// ChallengeType (e.g., http-01 → dns-01) deletes the old backend's cert
// before the new backend takes over.
func TestConversionDeletesOldCert(t *testing.T) {
	autocertBackend := newCountingBackend(0)
	dnsBackend := newCountingBackend(0)
	backends := map[string]CertBackend{
		"tls-alpn-01": autocertBackend,
		"http-01":     autocertBackend,
		"dns-01":      dnsBackend,
	}
	mgr, err := NewManager(ManagerConfig{CertDir: t.TempDir()}, backends, "tls-alpn-01", nil, nil, nil)
	require.NoError(t, err)

	const dom = "convert.example.com"
	_, err = mgr.AddDomain(dom, types.AccountID("acc"), types.ServiceID("svc"), AddDomainOptions{ChallengeType: "http-01"})
	require.NoError(t, err)
	drainPrefetch(t, mgr)
	require.Equal(t, 1, autocertBackend.IssuedCount(), "first AddDomain should issue via the http-01 backend")

	// Convert: same service, new ChallengeType.
	_, err = mgr.AddDomain(dom, types.AccountID("acc"), types.ServiceID("svc"), AddDomainOptions{ChallengeType: "dns-01"})
	require.NoError(t, err)
	drainPrefetch(t, mgr)

	assert.Equal(t, 1, autocertBackend.DeletedCount(),
		"conversion should delete the old backend's cert")
	assert.Equal(t, []string{dom}, autocertBackend.DeletedNames())
	assert.Equal(t, 1, dnsBackend.IssuedCount(),
		"new backend should issue once after conversion")
}

// TestRemoveDomainDeletesCert verifies that RemoveDomain cleans up the
// cert from the backend that owned the domain.
func TestRemoveDomainDeletesCert(t *testing.T) {
	backend := newCountingBackend(0)
	backends := map[string]CertBackend{"tls-alpn-01": backend}
	mgr, err := NewManager(ManagerConfig{CertDir: t.TempDir()}, backends, "tls-alpn-01", nil, nil, nil)
	require.NoError(t, err)

	const dom = "ephemeral.example.com"
	_, err = mgr.AddDomain(dom, types.AccountID("acc"), types.ServiceID("svc"), AddDomainOptions{})
	require.NoError(t, err)
	drainPrefetch(t, mgr)

	mgr.RemoveDomain(dom)
	assert.Equal(t, 1, backend.DeletedCount(), "RemoveDomain should delete the cached cert")
	assert.Equal(t, []string{dom}, backend.DeletedNames())
}

// TestIssueViaLegoUsesResolver — when a service has a dns_credentials_ref
// and the manager has a resolver, issueViaLego must call the resolver
// and pass the secret + provider into LegoBackend.Issue. We exercise
// the helper directly with a real *LegoBackend whose storage dir we
// pre-populate, so the whole prefetch loop doesn't need to run end-to-end.
func TestIssueViaLegoUsesResolver(t *testing.T) {
	tlsBackend := newCountingBackend(0)
	legoBackend, err := NewLegoBackend(LegoBackendConfig{CertDir: t.TempDir()})
	require.NoError(t, err)

	var (
		gotAccountID, gotRef string
	)
	resolver := func(_ context.Context, accountID, ref string) (string, string, error) {
		gotAccountID = accountID
		gotRef = ref
		return "resolved-secret", "cloudflare", nil
	}

	cfg := ManagerConfig{
		CertDir:           t.TempDir(),
		ResolveCredential: resolver,
	}
	backends := map[string]CertBackend{
		"tls-alpn-01": tlsBackend,
		"dns-01":      legoBackend,
	}
	mgr, err := NewManager(cfg, backends, "tls-alpn-01", nil, nil, nil)
	require.NoError(t, err)

	// Register a domain whose AddDomainOptions captures the cred ref.
	mgr.mu.Lock()
	mgr.domains[domain.Domain("test.example.com")] = &domainInfo{
		accountID:         types.AccountID("acc"),
		serviceID:         types.ServiceID("svc"),
		state:             domainPending,
		challengeType:     "dns-01",
		dnsProvider:       "cloudflare",
		dnsCredentialsRef: "cred-abc",
		backend:           legoBackend,
	}
	mgr.mu.Unlock()

	// issueViaLego will call legoBackend.Issue(...) which constructs a
	// real legoclient and tries to talk to ACME — it'll fail because the
	// ACME URL is fake, but the validation/resolution path runs first
	// and that's what we're verifying here.
	_ = mgr.issueViaLego(context.Background(), "test.example.com", "test.example.com", legoBackend)

	assert.Equal(t, "acc", gotAccountID, "resolver must be called with the registered account ID")
	assert.Equal(t, "cred-abc", gotRef, "resolver must be called with the registered ref")
}

// TestIssueViaLegoFallbackToEnvVar — when a service has no
// dns_credentials_ref, the manager must use its env-var fallback creds.
func TestIssueViaLegoFallbackToEnvVar(t *testing.T) {
	tlsBackend := newCountingBackend(0)
	legoBackend, err := NewLegoBackend(LegoBackendConfig{CertDir: t.TempDir()})
	require.NoError(t, err)

	resolverCalled := false
	resolver := func(_ context.Context, _, _ string) (string, string, error) {
		resolverCalled = true
		return "should-not-be-used", "", nil
	}

	cfg := ManagerConfig{
		CertDir:                  t.TempDir(),
		ResolveCredential:        resolver,
		FallbackDNSCredentials:   "env-secret",
		FallbackDNSProvider:      "cloudflare",
		FallbackACMEAccountEmail: "ops@example.com",
		FallbackACMEDirectoryURL: "https://acme.example/dir",
	}
	backends := map[string]CertBackend{
		"tls-alpn-01": tlsBackend,
		"dns-01":      legoBackend,
	}
	mgr, err := NewManager(cfg, backends, "tls-alpn-01", nil, nil, nil)
	require.NoError(t, err)

	mgr.mu.Lock()
	mgr.domains[domain.Domain("legacy.example.com")] = &domainInfo{
		accountID:     types.AccountID("acc"),
		serviceID:     types.ServiceID("svc"),
		state:         domainPending,
		challengeType: "dns-01",
		// No dns_credentials_ref → fallback path
		backend: legoBackend,
	}
	mgr.mu.Unlock()

	_ = mgr.issueViaLego(context.Background(), "legacy.example.com", "legacy.example.com", legoBackend)
	assert.False(t, resolverCalled, "resolver must not be called when no dns_credentials_ref is set")
}

// TestIssueViaLegoErrorsWhenNoCredsAvailable — service has dns-01 but
// neither a ref nor env-var fallback is configured.
func TestIssueViaLegoErrorsWhenNoCredsAvailable(t *testing.T) {
	tlsBackend := newCountingBackend(0)
	legoBackend, err := NewLegoBackend(LegoBackendConfig{CertDir: t.TempDir()})
	require.NoError(t, err)

	cfg := ManagerConfig{CertDir: t.TempDir()}
	backends := map[string]CertBackend{
		"tls-alpn-01": tlsBackend,
		"dns-01":      legoBackend,
	}
	mgr, err := NewManager(cfg, backends, "tls-alpn-01", nil, nil, nil)
	require.NoError(t, err)

	mgr.mu.Lock()
	mgr.domains[domain.Domain("orphan.example.com")] = &domainInfo{
		accountID:     types.AccountID("acc"),
		serviceID:     types.ServiceID("svc"),
		state:         domainPending,
		challengeType: "dns-01",
		backend:       legoBackend,
	}
	mgr.mu.Unlock()

	err = mgr.issueViaLego(context.Background(), "orphan.example.com", "orphan.example.com", legoBackend)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no DNS-01 credentials available")
}
