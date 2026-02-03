//go:build windows

package systemops

import (
	"net"
	"net/netip"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	testInterfaceName = "wg_bench_test"
	testInterfaceGUID = "{a1b2c3d4-e5f6-7890-abcd-ef1234567890}"
	testInterfaceMTU  = 1280
	benchmarkRoutes   = 4000
)

// BenchmarkRouteAddition benchmarks route addition using both interface-only and address-based methods.
func BenchmarkRouteAddition(b *testing.B) {
	log.SetLevel(log.WarnLevel)

	tunDev, ifaceIdx, cleanup := setupBenchmarkInterface(b)
	defer cleanup()

	gatewayIP := netip.MustParseAddr("10.200.0.254")

	b.Run("InterfaceOnly", func(b *testing.B) {
		benchmarkRouteMode(b, ifaceIdx, netip.Addr{}, benchmarkRoutes)
	})

	b.Run("WithGatewayAddress", func(b *testing.B) {
		benchmarkRouteMode(b, ifaceIdx, gatewayIP, benchmarkRoutes)
	})

	_ = tunDev
}

// TestRouteAdditionSpeed tests and compares route addition speed for both modes.
func TestRouteAdditionSpeed(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping route benchmark test in short mode")
	}

	log.SetLevel(log.WarnLevel)

	tunDev, ifaceIdx, cleanup := setupBenchmarkInterface(t)
	defer cleanup()

	gatewayIP := netip.MustParseAddr("10.200.0.254")
	numRoutes := benchmarkRoutes

	t.Logf("Testing route addition with %d routes on interface index %d", numRoutes, ifaceIdx)

	// Test interface-only mode
	t.Run("InterfaceOnly", func(t *testing.T) {
		routes := generateTestPrefixes(numRoutes, 0)
		nexthop := Nexthop{
			Intf: &net.Interface{Index: ifaceIdx},
		}

		start := time.Now()
		addedRoutes := addRoutesWithCleanup(t, routes, nexthop)
		addDuration := time.Since(start)

		t.Logf("Interface-only mode: added %d routes in %v (%.2f routes/sec)",
			addedRoutes, addDuration, float64(addedRoutes)/addDuration.Seconds())

		start = time.Now()
		deleteRoutes(t, routes[:addedRoutes], nexthop)
		deleteDuration := time.Since(start)

		t.Logf("Interface-only mode: deleted %d routes in %v (%.2f routes/sec)",
			addedRoutes, deleteDuration, float64(addedRoutes)/deleteDuration.Seconds())
	})

	// Test address-based mode
	t.Run("WithGatewayAddress", func(t *testing.T) {
		routes := generateTestPrefixes(numRoutes, 1)
		nexthop := Nexthop{
			IP:   gatewayIP,
			Intf: &net.Interface{Index: ifaceIdx},
		}

		start := time.Now()
		addedRoutes := addRoutesWithCleanup(t, routes, nexthop)
		addDuration := time.Since(start)

		t.Logf("Address-based mode: added %d routes in %v (%.2f routes/sec)",
			addedRoutes, addDuration, float64(addedRoutes)/addDuration.Seconds())

		start = time.Now()
		deleteRoutes(t, routes[:addedRoutes], nexthop)
		deleteDuration := time.Since(start)

		t.Logf("Address-based mode: deleted %d routes in %v (%.2f routes/sec)",
			addedRoutes, deleteDuration, float64(addedRoutes)/deleteDuration.Seconds())
	})

	_ = tunDev
}

// TestRouteAdditionSpeedComparison runs a direct comparison test and outputs results.
func TestRouteAdditionSpeedComparison(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping route benchmark comparison test in short mode")
	}

	log.SetLevel(log.WarnLevel)

	tunDev, ifaceIdx, cleanup := setupBenchmarkInterface(t)
	defer cleanup()

	gatewayIP := netip.MustParseAddr("10.200.0.254")
	numRoutes := benchmarkRoutes

	t.Logf("=== Route Addition Speed Comparison ===")
	t.Logf("Testing with %d routes on interface index %d", numRoutes, ifaceIdx)
	t.Logf("")

	// Interface-only mode test
	routesIfaceOnly := generateTestPrefixes(numRoutes, 0)
	nexthopIfaceOnly := Nexthop{
		Intf: &net.Interface{Index: ifaceIdx},
	}

	startIfaceOnly := time.Now()
	addedIfaceOnly := addRoutesWithCleanup(t, routesIfaceOnly, nexthopIfaceOnly)
	durationIfaceOnly := time.Since(startIfaceOnly)
	deleteRoutes(t, routesIfaceOnly[:addedIfaceOnly], nexthopIfaceOnly)

	// Address-based mode test
	routesWithAddr := generateTestPrefixes(numRoutes, 1)
	nexthopWithAddr := Nexthop{
		IP:   gatewayIP,
		Intf: &net.Interface{Index: ifaceIdx},
	}

	startWithAddr := time.Now()
	addedWithAddr := addRoutesWithCleanup(t, routesWithAddr, nexthopWithAddr)
	durationWithAddr := time.Since(startWithAddr)
	deleteRoutes(t, routesWithAddr[:addedWithAddr], nexthopWithAddr)

	// Output comparison results
	t.Logf("")
	t.Logf("=== Results ===")
	t.Logf("Interface-only mode (gateway=0.0.0.0):")
	t.Logf("  Routes added: %d", addedIfaceOnly)
	t.Logf("  Duration:     %v", durationIfaceOnly)
	t.Logf("  Speed:        %.2f routes/sec", float64(addedIfaceOnly)/durationIfaceOnly.Seconds())
	t.Logf("")
	t.Logf("Address-based mode (gateway=%s):", gatewayIP)
	t.Logf("  Routes added: %d", addedWithAddr)
	t.Logf("  Duration:     %v", durationWithAddr)
	t.Logf("  Speed:        %.2f routes/sec", float64(addedWithAddr)/durationWithAddr.Seconds())
	t.Logf("")

	if durationIfaceOnly < durationWithAddr {
		speedup := float64(durationWithAddr) / float64(durationIfaceOnly)
		t.Logf("Interface-only mode is %.2fx faster", speedup)
	} else {
		speedup := float64(durationIfaceOnly) / float64(durationWithAddr)
		t.Logf("Address-based mode is %.2fx faster", speedup)
	}

	_ = tunDev
}

func setupBenchmarkInterface(tb testing.TB) (*tun.NativeTun, int, func()) {
	tb.Helper()

	guid, err := windows.GUIDFromString(testInterfaceGUID)
	require.NoError(tb, err, "Failed to parse GUID")

	tunDevice, err := tun.CreateTUNWithRequestedGUID(testInterfaceName, &guid, testInterfaceMTU)
	require.NoError(tb, err, "Failed to create TUN device")

	nativeTun := tunDevice.(*tun.NativeTun)
	ifaceName, err := nativeTun.Name()
	require.NoError(tb, err, "Failed to get interface name")

	iface, err := net.InterfaceByName(ifaceName)
	require.NoError(tb, err, "Failed to get interface by name")

	tb.Logf("Created test interface: %s (index: %d)", ifaceName, iface.Index)

	// Assign an IP address to the interface using winipcfg
	assignInterfaceAddress(tb, nativeTun)

	cleanup := func() {
		if err := tunDevice.Close(); err != nil {
			tb.Logf("Failed to close TUN device: %v", err)
		}
	}

	return nativeTun, iface.Index, cleanup
}

func assignInterfaceAddress(tb testing.TB, nativeTun *tun.NativeTun) {
	tb.Helper()

	luid := winipcfg.LUID(nativeTun.LUID())
	addr := netip.MustParsePrefix("10.200.0.1/24")

	err := luid.SetIPAddresses([]netip.Prefix{addr})
	require.NoError(tb, err, "Failed to assign IP address to interface")

	// Allow the network stack to fully initialize the interface.
	time.Sleep(100 * time.Millisecond)

	tb.Logf("Assigned address %s to interface (LUID: %d)", addr, luid)
}

func generateTestPrefixes(count int, offset int) []netip.Prefix {
	prefixes := make([]netip.Prefix, count)

	// Generate unique /32 prefixes in the 172.16.0.0/12 range
	baseIP := 172<<24 | 16<<16

	for i := 0; i < count; i++ {
		ipNum := baseIP + i + (offset * count)
		ip := netip.AddrFrom4([4]byte{
			byte(ipNum >> 24),
			byte(ipNum >> 16),
			byte(ipNum >> 8),
			byte(ipNum),
		})
		prefixes[i] = netip.PrefixFrom(ip, 32)
	}

	return prefixes
}

func addRoutesWithCleanup(tb testing.TB, prefixes []netip.Prefix, nexthop Nexthop) int {
	tb.Helper()

	added := 0
	for _, prefix := range prefixes {
		if err := addRoute(prefix, nexthop); err != nil {
			tb.Logf("Failed to add route %s after %d successful additions: %v", prefix, added, err)
			break
		}
		added++
	}

	return added
}

func deleteRoutes(tb testing.TB, prefixes []netip.Prefix, nexthop Nexthop) {
	tb.Helper()

	for _, prefix := range prefixes {
		if err := deleteRoute(prefix, nexthop); err != nil {
			log.Debugf("Failed to delete route %s: %v", prefix, err)
		}
	}
}

func benchmarkRouteMode(b *testing.B, ifaceIdx int, gatewayIP netip.Addr, routeCount int) {
	b.Helper()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		prefixes := generateTestPrefixes(routeCount, i)
		nexthop := Nexthop{
			Intf: &net.Interface{Index: ifaceIdx},
		}
		if gatewayIP.IsValid() {
			nexthop.IP = gatewayIP
		}
		b.StartTimer()

		for _, prefix := range prefixes {
			if err := addRoute(prefix, nexthop); err != nil {
				b.Fatalf("Failed to add route: %v", err)
			}
		}

		b.StopTimer()
		for _, prefix := range prefixes {
			_ = deleteRoute(prefix, nexthop)
		}
	}
}
