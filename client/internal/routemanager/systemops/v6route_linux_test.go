//go:build linux && !android

package systemops

import (
	"errors"
	"net"
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
			return
		}
		t.Skipf("install IPv6 fallback default route: %v", err)
	}
	t.Cleanup(func() {
		if err := netlink.RouteDel(route); err != nil && !errors.Is(err, syscall.ESRCH) {
			t.Logf("delete IPv6 fallback default route: %v", err)
		}
	})
}
