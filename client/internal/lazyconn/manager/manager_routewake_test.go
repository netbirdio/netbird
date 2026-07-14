package manager

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/lazyconn"
	peerid "github.com/netbirdio/netbird/client/internal/peer/id"
	"github.com/netbirdio/netbird/client/internal/peerstore"
	"github.com/netbirdio/netbird/monotime"
	"github.com/netbirdio/netbird/route"
)

// mockEndpointManager is a thread-safe device.EndpointManager for tests.
type mockEndpointManager struct {
	mu        sync.Mutex
	endpoints map[netip.Addr]net.Conn
}

func newMockEndpointManager() *mockEndpointManager {
	return &mockEndpointManager{endpoints: make(map[netip.Addr]net.Conn)}
}

func (m *mockEndpointManager) SetEndpoint(fakeIP netip.Addr, conn net.Conn) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.endpoints[fakeIP] = conn
}

func (m *mockEndpointManager) RemoveEndpoint(fakeIP netip.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.endpoints, fakeIP)
}

// recordingWGIface implements lazyconn.WGIface (and bindProvider) in
// userspace-bind mode. The bind listener installs the peer's wake endpoint
// via UpdatePeer during construction, so the AllowedIPs it arms are recorded
// synchronously per peer key.
type recordingWGIface struct {
	mu      sync.Mutex
	lastIPs map[string][]netip.Prefix
	bind    *mockEndpointManager
}

func newRecordingWGIface() *recordingWGIface {
	return &recordingWGIface{
		lastIPs: make(map[string][]netip.Prefix),
		bind:    newMockEndpointManager(),
	}
}

func (m *recordingWGIface) UpdatePeer(peerKey string, allowedIps []netip.Prefix, _ time.Duration, _ *net.UDPAddr, _ *wgtypes.Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cloned := make([]netip.Prefix, len(allowedIps))
	copy(cloned, allowedIps)
	m.lastIPs[peerKey] = cloned
	return nil
}

func (m *recordingWGIface) allowedIPsFor(peerKey string) []netip.Prefix {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastIPs[peerKey]
}

func (m *recordingWGIface) RemovePeer(string) error { return nil }

func (m *recordingWGIface) IsUserspaceBind() bool { return true }

func (m *recordingWGIface) GetBind() device.EndpointManager { return m.bind }

func (m *recordingWGIface) Address() wgaddr.Address {
	return wgaddr.Address{
		IP:      netip.MustParseAddr("100.64.0.1"),
		Network: netip.MustParsePrefix("100.64.0.0/16"),
	}
}

func (m *recordingWGIface) LastActivities() map[string]monotime.Time { return nil }

func (m *recordingWGIface) MTU() uint16 { return 1280 }

// connKey provides a stable identity for deriving a peer connection ID.
type connKey struct{ id string }

func (c *connKey) ConnID() peerid.ConnID { return peerid.ConnID(c) }

func containsPrefix(prefixes []netip.Prefix, want netip.Prefix) bool {
	for _, p := range prefixes {
		if p == want {
			return true
		}
	}
	return false
}

func staticRoute(peer string, prefix netip.Prefix) *route.Route {
	return &route.Route{Peer: peer, Network: prefix, NetworkType: route.IPv4Network}
}

func overlayPeer(id string, overlay netip.Prefix) (*connKey, lazyconn.PeerConfig) {
	key := &connKey{id: id}
	return key, lazyconn.PeerConfig{
		PublicKey:  id,
		PeerConnID: key.ConnID(),
		AllowedIPs: []netip.Prefix{overlay},
		Log:        log.WithField("peer", id),
	}
}

// TestManager_RoutingPeer_ArmsWakeEndpointWithRoutedPrefix asserts that a
// routing peer's wake endpoint (installed via UpdatePeer when the activity
// listener is armed) covers the routed subnet, not just the overlay /32.
// The route is a single-peer (non-HA) route, which the HA-group builder
// skips, so it also guards that lone routing peers keep their subnet.
func TestManager_RoutingPeer_ArmsWakeEndpointWithRoutedPrefix(t *testing.T) {
	wg := newRecordingWGIface()
	mgr := NewManager(Config{}, context.Background(), peerstore.NewConnStore(), wg)

	routedNet := netip.MustParsePrefix("10.99.0.0/24")
	overlay := netip.MustParsePrefix("100.64.0.5/32")

	mgr.UpdateRouteHAMap(route.HAMap{"group-a": {staticRoute("peerA", routedNet)}})

	_, peerCfg := overlayPeer("peerA", overlay)
	_, err := mgr.AddPeer(peerCfg)
	require.NoError(t, err)

	armed := wg.allowedIPsFor("peerA")
	assert.True(t, containsPrefix(armed, routedNet),
		"wake endpoint AllowedIPs %v must contain routed subnet %s", armed, routedNet)
	assert.True(t, containsPrefix(armed, overlay),
		"wake endpoint AllowedIPs %v must still contain overlay %s", armed, overlay)
}

// TestManager_RouteChange_DropsStalePrefixOnReArm asserts that when a routed
// subnet moves away from a peer, a later idle->wake re-arm installs the new
// subnet and no longer carries the stale one. Because WireGuard AllowedIPs are
// peer-exclusive, a stale prefix would let this peer re-claim a subnet that has
// since moved to another HA peer, breaking failover routing.
func TestManager_RouteChange_DropsStalePrefixOnReArm(t *testing.T) {
	wg := newRecordingWGIface()
	mgr := NewManager(Config{}, context.Background(), peerstore.NewConnStore(), wg)

	oldNet := netip.MustParsePrefix("10.99.0.0/24")
	newNet := netip.MustParsePrefix("10.88.0.0/24")
	overlay := netip.MustParsePrefix("100.64.0.5/32")

	mgr.UpdateRouteHAMap(route.HAMap{"group-a": {staticRoute("peerA", oldNet)}})

	key, peerCfg := overlayPeer("peerA", overlay)
	_, err := mgr.AddPeer(peerCfg)
	require.NoError(t, err)
	require.True(t, containsPrefix(wg.allowedIPsFor("peerA"), oldNet), "initial arm must cover the old subnet")

	// Move the peer into the inactivity watcher so it can be re-armed.
	require.True(t, mgr.ActivatePeer("peerA"))

	// The subnet migrates away from peerA to a different subnet it now serves.
	mgr.UpdateRouteHAMap(route.HAMap{"group-a": {staticRoute("peerA", newNet)}})

	// The stored base must stay pristine (overlay-only), never accumulating
	// merged routed prefixes.
	mgr.managedPeersMu.Lock()
	stored := append([]netip.Prefix(nil), mgr.managedPeers["peerA"].AllowedIPs...)
	mgr.managedPeersMu.Unlock()
	assert.Equal(t, []netip.Prefix{overlay}, stored, "stored PeerConfig base must remain overlay-only")

	// Idle -> wake re-arm.
	mgr.DeactivatePeer(key.ConnID())

	armed := wg.allowedIPsFor("peerA")
	assert.True(t, containsPrefix(armed, newNet), "re-armed wake endpoint %v must contain new subnet %s", armed, newNet)
	assert.True(t, containsPrefix(armed, overlay), "re-armed wake endpoint %v must contain overlay %s", armed, overlay)
	assert.False(t, containsPrefix(armed, oldNet), "re-armed wake endpoint %v must NOT contain stale subnet %s", armed, oldNet)
}

// TestManager_MultiPeer_EachPeerKeepsOwnSubnet asserts that distinct routing
// peers each arm only their own routed subnet: no peer's prefixes leak into
// another's wake endpoint (which would let one peer steal the other's route).
func TestManager_MultiPeer_EachPeerKeepsOwnSubnet(t *testing.T) {
	wg := newRecordingWGIface()
	mgr := NewManager(Config{}, context.Background(), peerstore.NewConnStore(), wg)

	netA := netip.MustParsePrefix("10.99.0.0/24")
	netB := netip.MustParsePrefix("10.88.0.0/24")
	overlayA := netip.MustParsePrefix("100.64.0.5/32")
	overlayB := netip.MustParsePrefix("100.64.0.6/32")

	mgr.UpdateRouteHAMap(route.HAMap{
		"group-a": {staticRoute("peerA", netA)},
		"group-b": {staticRoute("peerB", netB)},
	})

	_, cfgA := overlayPeer("peerA", overlayA)
	_, cfgB := overlayPeer("peerB", overlayB)
	_, err := mgr.AddPeer(cfgA)
	require.NoError(t, err)
	_, err = mgr.AddPeer(cfgB)
	require.NoError(t, err)

	armedA := wg.allowedIPsFor("peerA")
	assert.True(t, containsPrefix(armedA, netA), "peerA %v must contain its own subnet %s", armedA, netA)
	assert.False(t, containsPrefix(armedA, netB), "peerA %v must NOT contain peerB subnet %s", armedA, netB)

	armedB := wg.allowedIPsFor("peerB")
	assert.True(t, containsPrefix(armedB, netB), "peerB %v must contain its own subnet %s", armedB, netB)
	assert.False(t, containsPrefix(armedB, netA), "peerB %v must NOT contain peerA subnet %s", armedB, netA)
}

// TestManager_DynamicRoute_NotMergedIntoWakeEndpoint asserts that dynamic
// (domain) routes are not merged into the wake endpoint: they have no fixed
// subnet the client can pre-install for wakeups.
func TestManager_DynamicRoute_NotMergedIntoWakeEndpoint(t *testing.T) {
	wg := newRecordingWGIface()
	mgr := NewManager(Config{}, context.Background(), peerstore.NewConnStore(), wg)

	overlay := netip.MustParsePrefix("100.64.0.5/32")

	dynamicRoute := &route.Route{
		Peer:        "peerA",
		NetworkType: route.DomainNetwork,
	}
	mgr.UpdateRouteHAMap(route.HAMap{"group-a": {dynamicRoute}})

	_, peerCfg := overlayPeer("peerA", overlay)
	_, err := mgr.AddPeer(peerCfg)
	require.NoError(t, err)

	armed := wg.allowedIPsFor("peerA")
	assert.Equal(t, []netip.Prefix{overlay}, armed,
		"dynamic route must not contribute prefixes; wake endpoint should be overlay-only, got %v", armed)
}

// TestManager_RemovePeer_ClearsRoutePrefixes guards against a map leak:
// removing a managed peer must drop its routed-prefix bookkeeping.
func TestManager_RemovePeer_ClearsRoutePrefixes(t *testing.T) {
	wg := newRecordingWGIface()
	mgr := NewManager(Config{}, context.Background(), peerstore.NewConnStore(), wg)

	mgr.UpdateRouteHAMap(route.HAMap{"group-a": {staticRoute("peerA", netip.MustParsePrefix("10.99.0.0/24"))}})

	_, peerCfg := overlayPeer("peerA", netip.MustParsePrefix("100.64.0.5/32"))
	_, err := mgr.AddPeer(peerCfg)
	require.NoError(t, err)

	mgr.RemovePeer("peerA")

	mgr.routesMu.RLock()
	_, ok := mgr.peerToRoutePrefixes["peerA"]
	mgr.routesMu.RUnlock()
	assert.False(t, ok, "peerToRoutePrefixes must not retain removed peer")
}

// TestManager_Close_ClearsRoutePrefixes guards the same map leak on close.
func TestManager_Close_ClearsRoutePrefixes(t *testing.T) {
	wg := newRecordingWGIface()
	mgr := NewManager(Config{}, context.Background(), peerstore.NewConnStore(), wg)

	mgr.UpdateRouteHAMap(route.HAMap{"group-a": {staticRoute("peerA", netip.MustParsePrefix("10.99.0.0/24"))}})

	mgr.close()

	mgr.routesMu.RLock()
	n := len(mgr.peerToRoutePrefixes)
	mgr.routesMu.RUnlock()
	assert.Equal(t, 0, n, "peerToRoutePrefixes must be empty after close")
}
