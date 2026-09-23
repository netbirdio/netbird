//go:build privileged

package sharedsock

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	nbnet "github.com/netbirdio/netbird/client/net"
)

// The probe must pick the source the raw sockets get on send, which carry the
// control-plane fwmark. The test installs the same shape of policy rule the client
// uses: unmarked traffic to 192.0.2.0/24 is diverted into a table that routes it
// via loopback, so an unmarked lookup reports 127.0.0.1 and a marked one does not.
func TestSrcProbe_HonoursControlPlaneMark(t *testing.T) {
	nbnet.Init()
	if !nbnet.AdvancedRouting() {
		t.Skip("advanced routing not supported")
	}

	const (
		table = 4242
		// Below the client's own rules, so a default route in the netbird table cannot win.
		priority = 90
	)
	dst := netip.MustParseAddr("192.0.2.1")

	marked, err := netlink.RouteGetWithOptions(net.IP(dst.AsSlice()), &netlink.RouteGetOptions{Mark: nbnet.ControlPlaneMark})
	if err != nil {
		t.Skipf("no route to %s: %v", dst, err)
	}
	if len(marked) == 0 || marked[0].Src == nil {
		t.Skipf("marked route to %s has no source address", dst)
	}
	markedSrc, ok := netip.AddrFromSlice(marked[0].Src)
	require.True(t, ok, "parse marked source")
	markedSrc = markedSrc.Unmap()
	if markedSrc == netip.MustParseAddr("127.0.0.1") {
		t.Skipf("marked route to %s already uses loopback, no contrast to test", dst)
	}

	rules, err := netlink.RuleList(unix.AF_INET)
	require.NoError(t, err)
	for _, r := range rules {
		if r.Priority == priority || r.Table == table {
			t.Skipf("rule priority %d or table %d already in use", priority, table)
		}
	}

	lo, err := netlink.LinkByName("lo")
	require.NoError(t, err)

	route := &netlink.Route{
		Dst:       &net.IPNet{IP: net.IPv4(192, 0, 2, 0), Mask: net.CIDRMask(24, 32)},
		LinkIndex: lo.Attrs().Index,
		// 127.0.0.1 is host-scoped, so a link-scoped route only picks it when told to.
		Src:   net.IPv4(127, 0, 0, 1),
		Table: table,
		Scope: netlink.SCOPE_LINK,
	}
	require.NoError(t, netlink.RouteAdd(route))
	t.Cleanup(func() { _ = netlink.RouteDel(route) })

	rule := netlink.NewRule()
	rule.Family = unix.AF_INET
	rule.Priority = priority
	rule.Table = table
	rule.Mark = nbnet.ControlPlaneMark
	rule.Invert = true
	require.NoError(t, netlink.RuleAdd(rule))
	t.Cleanup(func() { _ = netlink.RuleDel(rule) })

	unmarked, err := netlink.RouteGet(net.IP(dst.AsSlice()))
	require.NoError(t, err)
	require.NotEmpty(t, unmarked)
	require.True(t, unmarked[0].Src.Equal(net.IPv4(127, 0, 0, 1)), "unmarked lookup should be diverted to loopback, got %s", unmarked[0].Src)

	p, err := newSrcProbe(unix.AF_INET)
	require.NoError(t, err)
	t.Cleanup(func() { _ = p.close() })

	src, err := p.resolve(dst)
	require.NoError(t, err)
	assert.Equal(t, markedSrc, src, "probe should resolve the source of the marked lookup")
}
