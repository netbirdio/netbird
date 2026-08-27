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

// wgAllowedIPMock records the AddAllowedIP/RemoveAllowedIP calls made through the
// refcounter closures. It is not an iface.WGIface: Route reads r.wgInterface only on
// the iOS path, which this test does not exercise.
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

// RemoveRoute must release the allowed IPs itself even when it runs before
// RemoveAllowedIPs, the reversed order the manager used before this fix and that a
// future call site could reintroduce. The refcounter must stay usable for the next peer.
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
