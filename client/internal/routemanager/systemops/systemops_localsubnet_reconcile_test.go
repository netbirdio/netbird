//go:build !android && !ios && !js

package systemops

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/routemanager/notifier"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
)

var errTestDiscovery = errors.New("test discovery failure")

// testDiscovery drives host enumeration from an in-memory topology.
type testDiscovery struct {
	mu       sync.Mutex
	ifaces   []net.Interface
	addrs    map[string][]net.Addr
	ifaceErr error
	addrErr  map[string]error
	calls    atomic.Int32
}

func (d *testDiscovery) list() ([]net.Interface, error) {
	d.calls.Add(1)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.ifaceErr != nil {
		return nil, d.ifaceErr
	}
	return d.ifaces, nil
}

func (d *testDiscovery) addrsFor(intf net.Interface) ([]net.Addr, error) {
	d.calls.Add(1)
	d.mu.Lock()
	defer d.mu.Unlock()
	if err, ok := d.addrErr[intf.Name]; ok && err != nil {
		return nil, err
	}
	return d.addrs[intf.Name], nil
}

func testEth0(index int) net.Interface {
	return net.Interface{Index: index, Name: "eth0", Flags: net.FlagUp}
}

// expireLocalCache pushes the snapshot past every TTL so the next lookup re-enumerates.
func expireLocalCache(sysOps *SysOps) {
	sysOps.localSubnetsCacheMu.Lock()
	defer sysOps.localSubnetsCacheMu.Unlock()
	sysOps.localSubnetsCacheTime = time.Now().Add(-time.Hour)
}

func testSubnet(ip, cidr string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	if parsed := net.ParseIP(ip); parsed != nil {
		ipnet.IP = parsed
	}
	return ipnet
}

// newGuardSysOps builds a SysOps with stubbed discovery and table programming so tests never
// touch host interfaces or the routing table.
func newGuardSysOps(d *testDiscovery) (*SysOps, *atomic.Int32, *atomic.Int32) {
	var installs, removes atomic.Int32
	sysOps := &SysOps{
		wgInterface: &mockWGIface{
			address: wgaddr.Address{
				IP:      netip.MustParseAddr("100.64.0.1"),
				Network: netip.MustParsePrefix("100.64.0.0/16"),
			},
			name: "wt0",
		},
		notifier:       &notifier.Notifier{},
		listInterfaces: d.list,
		interfaceAddrs: d.addrsFor,
		installGuardedRoute: func(netip.Prefix, *net.Interface) error {
			installs.Add(1)
			return nil
		},
		removeGuardedRoute: func(netip.Prefix, *net.Interface) error {
			removes.Add(1)
			return nil
		},
	}
	return sysOps, &installs, &removes
}

func stubCounter() *refcounter.RouteRefCounter {
	return refcounter.New(
		func(netip.Prefix, struct{}) (struct{}, error) { return struct{}{}, nil },
		func(netip.Prefix, struct{}) error { return nil },
	)
}

// Enumeration failure must fail closed: no overlap may be reported as verified, and a new
// candidate route is withheld rather than installed over a subnet the cache missed.
func TestSysOps_DiscoveryFailureFailsClosed(t *testing.T) {
	d := &testDiscovery{ifaceErr: errTestDiscovery}
	sysOps, _, _ := newGuardSysOps(d)
	intf := &net.Interface{Index: 1, Name: "wt0"}

	_, overlap, healthy := sysOps.localSubnetOverlap(netip.MustParsePrefix("192.168.1.10/32"))
	assert.False(t, healthy, "failed discovery must not verify non-overlap")
	assert.False(t, overlap, "no subnet can be reported from a failed enumeration")

	isLocal, _, healthy := sysOps.isPrefixInLocalSubnets(netip.MustParsePrefix("192.168.1.10/32"))
	assert.False(t, healthy, "exclusion lookup must not verify either")
	assert.True(t, isLocal, "unverified exclusion lookup must fail closed")

	prefix := netip.MustParsePrefix("10.10.0.0/24")
	require.NoError(t, sysOps.AddVPNRoute(prefix, intf))
	assert.True(t, sysOps.isSuppressedVPNRoute(prefix), "route added during discovery failure must be withheld")
	_, installed := sysOps.takeInstalledVPNRoute(prefix)
	assert.False(t, installed, "withheld route must not reach the table")
}

// A failed refresh must retain the last validated snapshot instead of publishing the partial
// result, and recovery on the next refresh restores verified answers.
func TestSysOps_DiscoveryRetainsLastGood(t *testing.T) {
	d := &testDiscovery{
		ifaces: []net.Interface{testEth0(2)},
		addrs: map[string][]net.Addr{
			"eth0": {testSubnet("192.168.7.10", "192.168.7.0/24")},
		},
	}
	sysOps, _, _ := newGuardSysOps(d)

	_, overlap, healthy := sysOps.localSubnetOverlap(netip.MustParsePrefix("192.168.7.5/32"))
	require.True(t, healthy, "seed enumeration must verify")
	require.True(t, overlap, "seed subnet must be reported")

	d.mu.Lock()
	d.ifaceErr = errTestDiscovery
	d.mu.Unlock()
	expireLocalCache(sysOps)

	subnets, healthy := sysOps.localSubnets(localSubnetsGuardTTL)
	assert.False(t, healthy, "failed refresh must not verify")
	require.Len(t, subnets, 1, "failed refresh must retain the last validated snapshot")
	assert.True(t, subnets[0].Contains(net.ParseIP("192.168.7.5")), "retained snapshot must still cover the LAN")

	d.mu.Lock()
	d.ifaceErr = nil
	d.mu.Unlock()
	expireLocalCache(sysOps)

	_, overlap, healthy = sysOps.localSubnetOverlap(netip.MustParsePrefix("192.168.7.5/32"))
	assert.True(t, healthy, "recovery must verify again")
	assert.True(t, overlap, "recovered discovery must report the subnet")
}

// A per-interface address failure is partial discovery: the refresh is unverified even though
// other interfaces enumerated fine, and the previous snapshot is retained.
func TestSysOps_PartialDiscoveryFailsClosed(t *testing.T) {
	d := &testDiscovery{
		ifaces: []net.Interface{testEth0(2), {Index: 3, Name: "eth1", Flags: net.FlagUp}},
		addrs: map[string][]net.Addr{
			"eth0": {testSubnet("192.168.7.10", "192.168.7.0/24")},
			"eth1": {testSubnet("10.20.0.5", "10.20.0.0/16")},
		},
	}
	sysOps, _, _ := newGuardSysOps(d)

	_, _, healthy := sysOps.localSubnetOverlap(netip.MustParsePrefix("10.99.0.1/32"))
	require.True(t, healthy, "full enumeration must verify")

	d.mu.Lock()
	d.addrErr = map[string]error{"eth1": errTestDiscovery}
	d.mu.Unlock()
	expireLocalCache(sysOps)

	_, _, healthy = sysOps.localSubnetOverlap(netip.MustParsePrefix("10.99.0.1/32"))
	assert.False(t, healthy, "partial discovery must not verify non-overlap")

	subnets, _ := sysOps.localSubnets(localSubnetsGuardTTL)
	require.Len(t, subnets, 2, "partial refresh must retain the last validated snapshot")

	prefix := netip.MustParsePrefix("10.99.0.0/24")
	require.NoError(t, sysOps.AddVPNRoute(prefix, &net.Interface{Index: 1, Name: "wt0"}))
	assert.True(t, sysOps.isSuppressedVPNRoute(prefix), "route added during partial discovery must be withheld")
}

// A route installed before its subnet appeared must leave the table once reconciliation
// observes the overlap, while the holder stays counted.
func TestSysOps_ReconcileRemovesShadowingRoute(t *testing.T) {
	d := &testDiscovery{}
	sysOps, _, removes := newGuardSysOps(d)
	counter := stubCounter()
	prefix := netip.MustParsePrefix("192.168.1.10/32")
	intf := &net.Interface{Index: 1, Name: "wt0"}

	_, err := counter.Increment(prefix, struct{}{})
	require.NoError(t, err)
	sysOps.trackInstalledVPNRoute(prefix, intf)

	d.mu.Lock()
	d.ifaces = []net.Interface{testEth0(2)}
	d.addrs = map[string][]net.Addr{"eth0": {testSubnet("192.168.1.10", "192.168.1.0/24")}}
	d.mu.Unlock()

	require.NoError(t, sysOps.ReconcileLocalSubnets(counter))
	assert.EqualValues(t, 1, removes.Load(), "shadowing route must leave the table")
	assert.True(t, sysOps.isSuppressedVPNRoute(prefix), "removed route must be marked withheld")
	_, ok := counter.Get(prefix)
	assert.True(t, ok, "holder must stay counted while withheld")

	// Repetition without topology change must be a no-op.
	require.NoError(t, sysOps.ReconcileLocalSubnets(counter))
	assert.EqualValues(t, 1, removes.Load(), "repetition must not reprogram the table")
}

// A withheld route must be reinstalled once its subnet disappears, and a stale mark whose
// holder is gone must be dropped without touching the table.
func TestSysOps_ReconcileReinstallsWithheldRoute(t *testing.T) {
	d := &testDiscovery{
		ifaces: []net.Interface{testEth0(2)},
		addrs:  map[string][]net.Addr{"eth0": {testSubnet("192.168.1.10", "192.168.1.0/24")}},
	}
	sysOps, installs, _ := newGuardSysOps(d)
	lan := netip.MustParsePrefix("192.168.1.10/32")
	stale := netip.MustParsePrefix("192.168.1.11/32")
	intf := &net.Interface{Index: 1, Name: "wt0"}

	// Drive the production withhold path through a refcounter so holder accounting is real.
	counter := refcounter.New(
		func(p netip.Prefix, _ struct{}) (struct{}, error) {
			return struct{}{}, sysOps.AddVPNRoute(p, intf)
		},
		func(p netip.Prefix, _ struct{}) error {
			return sysOps.RemoveVPNRoute(p, intf)
		},
	)
	_, err := counter.Increment(lan, struct{}{})
	require.NoError(t, err)
	assert.True(t, sysOps.isSuppressedVPNRoute(lan), "overlapping route must be withheld")
	sysOps.suppressVPNRoute(stale, intf)

	d.mu.Lock()
	d.ifaces = nil
	d.addrs = map[string][]net.Addr{}
	d.mu.Unlock()

	// The install seam is stubbed, so point the withheld entries at it for this pass.
	sysOps.installGuardedRoute = func(p netip.Prefix, _ *net.Interface) error {
		installs.Add(1)
		sysOps.trackInstalledVPNRoute(p, intf)
		return nil
	}

	require.NoError(t, sysOps.ReconcileLocalSubnets(counter))
	assert.EqualValues(t, 1, installs.Load(), "only the held route may be reinstalled, not the stale mark")
	assert.False(t, sysOps.isSuppressedVPNRoute(lan), "reinstalled route must clear the mark")
	assert.False(t, sysOps.isSuppressedVPNRoute(stale), "stale mark without a holder must be dropped")
	_, installed := sysOps.takeInstalledVPNRoute(lan)
	assert.True(t, installed, "reinstalled route must be mirrored")
}

// Synthetic split-default halves are mirrored for idempotent teardown but refcounted under the
// parent default, so per-prefix reconciliation must skip them. Forgetting a split mark (its key
// is absent from the refcounter) without deleting the OS route would strand the route: shutdown
// then finds no mirror entry to remove it against.
func TestSysOps_ReconcileKeepsSplitDefaultRoutes(t *testing.T) {
	d := &testDiscovery{
		ifaces: []net.Interface{testEth0(2)},
		addrs:  map[string][]net.Addr{"eth0": {testSubnet("10.0.0.5", "10.0.0.0/24")}},
	}
	sysOps, _, removes := newGuardSysOps(d)
	counter := stubCounter()
	intf := &net.Interface{Index: 1, Name: "wt0"}

	// The refcounter only ever holds the parent default, never the /1 halves.
	splits := []netip.Prefix{splitDefaultv4_1, splitDefaultv4_2, splitDefaultv6_1, splitDefaultv6_2}
	for _, split := range splits {
		sysOps.trackInstalledVPNRoute(split, intf)
	}

	require.NoError(t, sysOps.ReconcileLocalSubnets(counter))

	installed, _ := sysOps.vpnRoutesSnapshot()
	for _, split := range splits {
		_, ok := installed[split]
		assert.Truef(t, ok, "split-default %s must stay mirrored for teardown", split)
	}
	assert.EqualValues(t, 0, removes.Load(), "split-default routes must not be reprogrammed")
}

// Concurrent adds, removes, and reconciliations must not race or leak guard marks.
func TestSysOps_ConcurrentRouteUpdates(t *testing.T) {
	d := &testDiscovery{
		ifaces: []net.Interface{testEth0(2)},
		addrs:  map[string][]net.Addr{"eth0": {testSubnet("192.168.1.10", "192.168.1.0/24")}},
	}
	sysOps, _, _ := newGuardSysOps(d)
	intf := &net.Interface{Index: 1, Name: "wt0"}
	counter := refcounter.New(
		func(p netip.Prefix, _ struct{}) (struct{}, error) {
			return struct{}{}, sysOps.AddVPNRoute(p, intf)
		},
		func(p netip.Prefix, _ struct{}) error {
			return sysOps.RemoveVPNRoute(p, intf)
		},
	)

	prefixes := make([]netip.Prefix, 0, 8)
	for i := 1; i <= 8; i++ {
		prefixes = append(prefixes, netip.MustParsePrefix(fmt.Sprintf("192.168.1.%d/32", i)))
	}

	var wg sync.WaitGroup
	for _, prefix := range prefixes {
		wg.Add(1)
		go func(p netip.Prefix) {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				if _, err := counter.Increment(p, struct{}{}); err != nil {
					t.Errorf("increment %s: %v", p, err)
					return
				}
				if _, err := counter.Decrement(p); err != nil {
					t.Errorf("decrement %s: %v", p, err)
					return
				}
			}
		}(prefix)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 25; j++ {
			if err := sysOps.ReconcileLocalSubnets(counter); err != nil {
				t.Errorf("reconcile: %v", err)
				return
			}
		}
	}()
	wg.Wait()

	assert.Empty(t, counter.Keys(), "all holders are gone, nothing may stay counted")
	installed, suppressed := sysOps.vpnRoutesSnapshot()
	assert.Empty(t, installed, "no installed mirror may leak without holders")
	assert.Empty(t, suppressed, "no withheld mark may leak without holders")
}
