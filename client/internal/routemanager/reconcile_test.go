//go:build !windows

package routemanager

import (
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
)

// reconcileWGMock is a minimal iface.WGIface that only records AddAllowedIP calls; every other
// method is an inert stub because ReconcilePeerAllowedIPs exercises none of them.
type reconcileWGMock struct {
	mu   sync.Mutex
	adds map[string][]netip.Prefix
}

func (m *reconcileWGMock) AddAllowedIP(peerKey string, allowedIP netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.adds == nil {
		m.adds = map[string][]netip.Prefix{}
	}
	m.adds[peerKey] = append(m.adds[peerKey], allowedIP)
	return nil
}

func (m *reconcileWGMock) added(peerKey string) []netip.Prefix {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.adds[peerKey]
}

func (m *reconcileWGMock) RemoveAllowedIP(string, netip.Prefix) error { return nil }
func (m *reconcileWGMock) Name() string                               { return "utun-test" }
func (m *reconcileWGMock) Address() wgaddr.Address                    { return wgaddr.Address{} }
func (m *reconcileWGMock) ToInterface() *net.Interface                { return nil }
func (m *reconcileWGMock) IsUserspaceBind() bool                      { return false }
func (m *reconcileWGMock) GetFilter() device.PacketFilter             { return nil }
func (m *reconcileWGMock) GetDevice() *device.FilteredDevice          { return nil }
func (m *reconcileWGMock) GetNet() *netstack.Net                      { return nil }

// TestReconcilePeerAllowedIPs verifies the declarative reconcile re-applies every routed prefix
// tracked for the peer (self-heal, independent of refcount level) and stays scoped to that peer.
func TestReconcilePeerAllowedIPs(t *testing.T) {
	wg := &reconcileWGMock{}
	m := &DefaultManager{wgInterface: wg}
	m.allowedIPsRefCounter = refcounter.New[netip.Prefix, string, string](
		func(_ netip.Prefix, peerKey string) (string, error) { return peerKey, nil },
		func(netip.Prefix, string) error { return nil },
	)

	peerA1 := netip.MustParsePrefix("10.0.0.0/24")
	peerA2 := netip.MustParsePrefix("10.1.0.0/24")
	peerB1 := netip.MustParsePrefix("10.2.0.0/24")

	for prefix, peer := range map[netip.Prefix]string{peerA1: "peerA", peerA2: "peerA", peerB1: "peerB"} {
		_, err := m.allowedIPsRefCounter.Increment(prefix, peer)
		require.NoError(t, err)
	}
	// Extra reference: reconcile must still re-apply the prefix even though its refcount never
	// hit 0 again (the exact case the plain incremental path skips).
	_, err := m.allowedIPsRefCounter.Increment(peerA1, "peerA")
	require.NoError(t, err)

	require.NoError(t, m.ReconcilePeerAllowedIPs("peerA"))

	assert.ElementsMatch(t, []netip.Prefix{peerA1, peerA2}, wg.added("peerA"),
		"reconcile must re-apply all routed prefixes of the peer")
	assert.Empty(t, wg.added("peerB"), "reconcile must not touch another peer's prefixes")
}

// TestReconcilePeerAllowedIPsNoCounter verifies reconcile is a safe no-op before the refcounter is
// set up.
func TestReconcilePeerAllowedIPsNoCounter(t *testing.T) {
	wg := &reconcileWGMock{}
	m := &DefaultManager{wgInterface: wg}

	require.NoError(t, m.ReconcilePeerAllowedIPs("peerA"))
	assert.Empty(t, wg.added("peerA"))
}
