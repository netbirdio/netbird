package acme

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/domain"
)

func TestAddDomainPreservesLegacyReplacement(t *testing.T) {
	wcDir := t.TempDir()
	generateSelfSignedCert(t, wcDir, "example", "*.example.com")
	mgr, err := NewManager(ManagerConfig{CertDir: t.TempDir(), WildcardDir: wcDir}, nil, nil, nil)
	require.NoError(t, err)
	require.True(t, mgr.AddDomain("foo.example.com", "old-account", "old-service"), "wildcard registration must be synchronous")
	require.True(t, mgr.AddDomain("foo.example.com", "new-account", "new-service"), "legacy API must replace the registration")
	assert.False(t, mgr.RemoveDomainForService("foo.example.com", "old-service"), "previous owner must not remove its replacement")
	assert.True(t, mgr.RemoveDomainForService("foo.example.com", "new-service"), "replacement must own the domain")
	assert.Zero(t, mgr.TotalDomains(), "replacement removal must delete the domain")
}

func TestACMEDomainOwnershipPreventsStaleRemoval(t *testing.T) {
	// A local failing endpoint drains prefetch without accessing a real CA.
	ca := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "test certificate authority unavailable", http.StatusBadRequest)
	}))
	t.Cleanup(ca.Close)
	mgr, err := NewManager(ManagerConfig{CertDir: t.TempDir(), ACMEURL: ca.URL}, nil, nil, nil)
	require.NoError(t, err)
	d := domain.Domain("acme.example.test")
	wildcard, ok := mgr.AddDomainForService(d, "acct", "new-service")
	require.True(t, ok, "unowned ACME domain must be registered")
	assert.False(t, wildcard, "this domain must exercise ACME registration")
	_, ok = mgr.AddDomainForService(d, "other-account", "old-service")
	assert.False(t, ok, "another service must not overwrite ACME ownership")
	assert.False(t, mgr.RemoveDomainForService(d, "old-service"), "stale removal must preserve the domain")
	assert.Equal(t, 1, mgr.TotalDomains(), "rejected operations must preserve the registered domain")
	require.Eventually(t, func() bool { return mgr.PendingCerts() == 0 }, 5*time.Second, 10*time.Millisecond,
		"prefetch must finish before removing its state and temporary cache")
	assert.True(t, mgr.RemoveDomainForService(d, "new-service"), "current owner must be able to remove the domain")
	assert.Zero(t, mgr.TotalDomains(), "successful removal must delete the domain")
}
