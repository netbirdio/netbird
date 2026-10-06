//go:build linux && !android && privileged

package systemops

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

// ensureIPv6DefaultRoute installs a low-preference IPv6 default route via the
// loopback interface so route lookups for global IPv6 prefixes resolve in
// environments without v6 connectivity. Any pre-existing default route wins
// because of its lower metric.
func ensureIPv6DefaultRoute(t *testing.T) {
	t.Helper()

	lo, err := netlink.LinkByName("lo")
	require.NoError(t, err, "find loopback interface")

	route := &netlink.Route{
		Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
		LinkIndex: lo.Attrs().Index,
		Priority:  1 << 20,
	}
	if err := netlink.RouteAdd(route); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			requireUsableIPv6Nexthop(t)
			return
		}
		t.Skipf("install IPv6 fallback default route: %v", err)
	}
	t.Cleanup(func() {
		if err := netlink.RouteDel(route); err != nil && !errors.Is(err, syscall.ESRCH) {
			t.Logf("delete IPv6 fallback default route: %v", err)
		}
	})

	requireUsableIPv6Nexthop(t)
}

// requireUsableIPv6Nexthop skips the test unless the resolved IPv6 default
// nexthop can actually carry a route. Installing the default route succeeding
// does not imply the kernel accepts it as a nexthop for a concrete prefix.
func requireUsableIPv6Nexthop(t *testing.T) {
	t.Helper()

	nexthop, err := GetNextHop(netip.IPv6Unspecified())
	if err != nil {
		t.Skipf("resolve IPv6 default nexthop: %v", err)
	}

	probe := &netlink.Route{
		Scope:  netlink.SCOPE_UNIVERSE,
		Table:  syscall.RT_TABLE_MAIN,
		Family: netlink.FAMILY_V6,
		Dst:    &net.IPNet{IP: net.ParseIP("100::64"), Mask: net.CIDRMask(128, 128)},
	}
	require.NoError(t, addNextHop(nexthop, probe), "build IPv6 probe route")

	switch err := netlink.RouteAdd(probe); {
	case err == nil:
		if err := netlink.RouteDel(probe); err != nil && !errors.Is(err, syscall.ESRCH) {
			t.Logf("delete IPv6 probe route: %v", err)
		}
	case errors.Is(err, syscall.EEXIST):
	default:
		t.Skipf("IPv6 nexthop %s unusable for route installation: %v", nexthop, err)
	}
}
