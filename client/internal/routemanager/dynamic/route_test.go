package dynamic

import (
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

// wgAllowedIPMock records AddAllowedIP/RemoveAllowedIP calls made through the refcounter's
// add/remove closures. It doesn't implement iface.WGIface - Route only reads r.wgInterface from
// route_ios.go, a path this test doesn't exercise, so the mock is wired in via the refcounter
// closures below instead of common.HandlerParams.WgInterface.
type wgAllowedIPMock struct {
	mu      sync.Mutex
	added   map[string][]netip.Prefix
	removed map[string][]netip.Prefix
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
	if m.removed == nil {
		m.removed = map[string][]netip.Prefix{}
	}
	m.removed[peerKey] = append(m.removed[peerKey], allowedIP)
	return nil
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

// TestRemoveRouteReleasesAllowedIPs exercises RemoveRoute and RemoveAllowedIPs in the reversed
// order - RemoveRoute first, RemoveAllowedIPs second - that the manager used before its fix and
// that some future call site could reintroduce by mistake. It's a regression guard for
// RemoveRoute's safety net: even in that order, the old peer's allowed IP must still be released,
// and the allowed IPs refcounter must be left usable for a subsequent peer. The manager itself now
// calls RemoveAllowedIPs (via stopObsoleteClients) before RemoveRoute (via updateSystemRoutes);
// that correct order isn't what's under test here.
func TestRemoveRouteReleasesAllowedIPs(t *testing.T) {
	wg := &wgAllowedIPMock{}

	routeRefCounter := refcounter.New(
		func(netip.Prefix, struct{}) (struct{}, error) { return struct{}{}, nil },
		func(netip.Prefix, struct{}) error { return nil },
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

	require.NoError(t, r.AddAllowedIPs("peerA"))
	assert.Equal(t, []netip.Prefix{prefix}, wg.addedFor("peerA"))

	// Reversed order: RemoveRoute runs before RemoveAllowedIPs. RemoveRoute must release the
	// allowed IPs itself since it's about to wipe dynamicDomains, the state RemoveAllowedIPs
	// would otherwise need. The later RemoveAllowedIPs call must then be a safe no-op.
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
