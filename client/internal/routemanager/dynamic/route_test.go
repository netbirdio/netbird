package dynamic

import (
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager/common"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

// wgAllowedIPMock records the AddAllowedIP/RemoveAllowedIP calls made through the
// refcounter closures. It is not an iface.WGIface: Route reads r.wgInterface only on
// the iOS path, which this test does not exercise.
type wgAllowedIPMock struct {
	mu             sync.Mutex
	added          map[string][]netip.Prefix
	removed        map[string][]netip.Prefix
	removeFailures int
	removeByPrefix map[netip.Prefix]int
	removeAttempts int
}

type routeCleanupMock struct {
	mu             sync.Mutex
	removeFailures int
	removeAttempts int
}

func (m *routeCleanupMock) RemoveRoute(netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeAttempts++
	if m.removeFailures != 0 {
		if m.removeFailures > 0 {
			m.removeFailures--
		}
		return errors.New("remove route")
	}
	return nil
}

func (m *routeCleanupMock) attempts() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.removeAttempts
}

func (m *wgAllowedIPMock) AddAllowedIP(peerKey string, allowedIP netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.added == nil {
		m.added = map[string][]netip.Prefix{}
	}
	m.added[peerKey] = append(m.added[peerKey], allowedIP)
	return nil
}

func (m *wgAllowedIPMock) RemoveAllowedIP(peerKey string, allowedIP netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeAttempts++
	if m.removeByPrefix[allowedIP] != 0 {
		if m.removeByPrefix[allowedIP] > 0 {
			m.removeByPrefix[allowedIP]--
		}
		return errors.New("remove allowed IP")
	}
	if m.removeFailures != 0 {
		if m.removeFailures > 0 {
			m.removeFailures--
		}
		return errors.New("remove allowed IP")
	}
	if m.removed == nil {
		m.removed = map[string][]netip.Prefix{}
	}
	m.removed[peerKey] = append(m.removed[peerKey], allowedIP)
	return nil
}

func (m *wgAllowedIPMock) attempts() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.removeAttempts
}

func (m *wgAllowedIPMock) addedFor(peerKey string) []netip.Prefix {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.added[peerKey]
}

func (m *wgAllowedIPMock) removedFor(peerKey string) []netip.Prefix {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.removed[peerKey]
}

// RemoveRoute must release the allowed IPs itself even when it runs before
// RemoveAllowedIPs, the reversed order the manager used before this fix and that a
// future call site could reintroduce. The refcounter must stay usable for the next peer.
func TestRemoveRouteReleasesAllowedIPs(t *testing.T) {
	wg := &wgAllowedIPMock{}
	r, prefix := newRouteWithAllowedIP(t, wg)
	assert.Equal(t, []netip.Prefix{prefix}, wg.addedFor("peerA"))

	// Reversed order: RemoveRoute first. It must release the allowed IPs itself, since it
	// wipes dynamicDomains, and the later RemoveAllowedIPs must then be a safe no-op.
	require.NoError(t, r.RemoveRoute())
	require.NoError(t, r.RemoveAllowedIPs())

	assert.Equal(t, []netip.Prefix{prefix}, wg.removedFor("peerA"),
		"peerA's allowed IP must have been released despite the reversed call order")

	t.Run("refcounter is usable for a subsequent peer", func(t *testing.T) {
		_, err := r.allowedIPsRefcounter.Increment(prefix, "peerB")
		require.NoError(t, err)
		assert.Equal(t, []netip.Prefix{prefix}, wg.addedFor("peerB"),
			"refcounter must have been fully released, allowing a new peer to take the prefix")
	})
}

func TestRemoveRouteRetriesAllowedIPCleanup(t *testing.T) {
	wg := &wgAllowedIPMock{removeFailures: 1}
	r, prefix := newRouteWithAllowedIP(t, wg)

	require.Error(t, r.RemoveRoute(), "the first allowed IP removal fails")
	assertRouteCleanupPending(t, r, "peerA", prefix)
	assert.Empty(t, wg.removedFor("peerA"), "the failed removal must not be recorded as complete")

	require.NoError(t, r.RemoveRoute(), "a later route reconciliation retries the cleanup")
	assertRouteCleanupComplete(t, r)
	assert.Equal(t, []netip.Prefix{prefix}, wg.removedFor("peerA"),
		"the retry must remove the old peer's allowed IP")
	assert.Equal(t, 2, wg.attempts(), "the removal must be attempted again")
}

func TestRemoveRoutePreservesAllowedIPCleanupAfterPersistentFailure(t *testing.T) {
	wg := &wgAllowedIPMock{removeFailures: -1}
	r, prefix := newRouteWithAllowedIP(t, wg)

	for range 2 {
		require.Error(t, r.RemoveRoute(), "a failed cleanup must keep the route retryable")
		assertRouteCleanupPending(t, r, "peerA", prefix)
	}

	assert.Empty(t, wg.removedFor("peerA"), "a persistently failing removal must not be marked complete")
	assert.Equal(t, 2, wg.attempts(), "every reconciliation must retry the removal")
}

func TestRemoveAllowedIPsRetriesOnlyFailedPrefix(t *testing.T) {
	prefixA := netip.MustParsePrefix("203.0.113.7/32")
	prefixB := netip.MustParsePrefix("203.0.113.8/32")
	wg := &wgAllowedIPMock{removeByPrefix: map[netip.Prefix]int{prefixB: 1}}
	r, _ := newRouteWithAllowedIP(t, wg)
	addDynamicPrefix(t, r, domain.Domain("example.com"), prefixB, "peerA")

	// A second handler owns this reference. The retry must leave it intact.
	_, err := r.allowedIPsRefcounter.Increment(prefixA, "peerA")
	require.NoError(t, err)

	require.Error(t, r.RemoveAllowedIPs(), "the first removal of prefix B fails")
	require.NoError(t, r.RemoveAllowedIPs(), "the retry removes only the pending prefix B")
	assert.Equal(t, []netip.Prefix{prefixB}, wg.removedFor("peerA"),
		"prefix A's other owner must keep it installed")

	_, err = r.allowedIPsRefcounter.Decrement(prefixA, "peerA")
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{prefixB, prefixA}, wg.removedFor("peerA"),
		"removing prefix A must be deferred to its other owner")
	assert.Equal(t, 3, wg.attempts(), "prefix A must not be decremented during the retry")
}

func TestRemoveAllowedIPsReleasesDuplicatePrefixesAcrossDomains(t *testing.T) {
	prefix := netip.MustParsePrefix("203.0.113.7/32")
	wg := &wgAllowedIPMock{removeFailures: 1}
	r, _ := newRouteWithAllowedIP(t, wg)
	addDynamicPrefix(t, r, domain.Domain("other.example.com"), prefix, "peerA")

	require.Error(t, r.RemoveAllowedIPs(), "the final same-prefix removal fails once")
	require.NoError(t, r.RemoveAllowedIPs(), "the pending removal is retried once")
	assert.Equal(t, []netip.Prefix{prefix}, wg.removedFor("peerA"),
		"the final of two same-prefix references must remove the allowed IP once")
	assert.Equal(t, 2, wg.attempts(), "only the failed final removal is retried")
}

func TestRemoveRouteRetriesFailedSystemRouteCleanup(t *testing.T) {
	wg := &wgAllowedIPMock{}
	systemRoutes := &routeCleanupMock{removeFailures: 1}
	r, prefix := newRouteWithCleanupMocks(t, wg, systemRoutes)

	require.Error(t, r.RemoveRoute(), "the first system route removal fails")
	assertRoutePrefixesPending(t, r, prefix)
	assert.Equal(t, []netip.Prefix{prefix}, wg.removedFor("peerA"),
		"allowed IP cleanup must not be repeated after it succeeds")

	require.NoError(t, r.RemoveRoute(), "a later route reconciliation retries the system route cleanup")
	assertRouteCleanupComplete(t, r)
	assert.Equal(t, 2, systemRoutes.attempts(), "the system route removal must be attempted again")
}

func newRouteWithAllowedIP(t *testing.T, wg *wgAllowedIPMock) (*Route, netip.Prefix) {
	return newRouteWithCleanupMocks(t, wg, nil)
}

func newRouteWithCleanupMocks(t *testing.T, wg *wgAllowedIPMock, systemRoutes *routeCleanupMock) (*Route, netip.Prefix) {
	t.Helper()

	routeRefCounter := refcounter.New(
		func(netip.Prefix, struct{}) (struct{}, error) { return struct{}{}, nil },
		func(prefix netip.Prefix, _ struct{}) error {
			if systemRoutes == nil {
				return nil
			}
			return systemRoutes.RemoveRoute(prefix)
		},
	)
	allowedIPsRefCounter := refcounter.NewAllowedIPs(
		func(prefix netip.Prefix, peerKey string) (string, error) {
			return peerKey, wg.AddAllowedIP(peerKey, prefix)
		},
		func(prefix netip.Prefix, peerKey string) error {
			return wg.RemoveAllowedIP(peerKey, prefix)
		},
	)

	r := NewRoute(common.HandlerParams{
		Route: &route.Route{
			ID:      "testroute:1",
			Domains: domain.List{domain.Domain("example.com")},
		},
		RouteRefCounter:      routeRefCounter,
		AllowedIPsRefCounter: allowedIPsRefCounter,
		StatusRecorder:       peer.NewRecorder("https://mgm"),
	}, netip.AddrPort{})
	prefix := netip.MustParsePrefix("203.0.113.7/32")
	r.dynamicDomains = domainMap{
		domain.Domain("example.com"): {prefix},
	}

	_, err := r.routeRefCounter.Increment(prefix, struct{}{})
	require.NoError(t, err)
	require.NoError(t, r.AddAllowedIPs("peerA"))
	return r, prefix
}

func assertRouteCleanupPending(t *testing.T, r *Route, peerKey string, prefix netip.Prefix) {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()
	assert.Equal(t, peerKey, r.currentPeerKey, "the peer key is needed for the next cleanup attempt")
	assert.Equal(t, []netip.Prefix{prefix}, r.dynamicDomains[domain.Domain("example.com")],
		"the prefixes are needed for the next cleanup attempt")
}

func assertRouteCleanupComplete(t *testing.T, r *Route) {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()
	assert.Empty(t, r.currentPeerKey, "the peer key must clear after successful cleanup")
	assert.Empty(t, r.dynamicDomains, "the dynamic domains must clear after successful cleanup")
}

func assertRoutePrefixesPending(t *testing.T, r *Route, prefix netip.Prefix) {
	t.Helper()

	r.mu.Lock()
	defer r.mu.Unlock()
	assert.Empty(t, r.currentPeerKey, "allowed IP cleanup already succeeded")
	assert.Equal(t, []netip.Prefix{prefix}, r.dynamicDomains[domain.Domain("example.com")],
		"the failed system route prefix is needed for the next cleanup attempt")
}

func addDynamicPrefix(t *testing.T, r *Route, d domain.Domain, prefix netip.Prefix, peerKey string) {
	t.Helper()

	_, err := r.routeRefCounter.Increment(prefix, struct{}{})
	require.NoError(t, err)

	r.mu.Lock()
	defer r.mu.Unlock()
	r.dynamicDomains[d] = append(r.dynamicDomains[d], prefix)
	require.NoError(t, r.incrementAllowedIP(d, prefix, peerKey))
}
