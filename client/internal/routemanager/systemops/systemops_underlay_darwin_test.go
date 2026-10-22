//go:build darwin && !ios

package systemops

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
)

func v4(a, b, c, d byte) *route.Inet4Addr { return &route.Inet4Addr{IP: [4]byte{a, b, c, d}} }

func routeMsg(index int, flags int, dst, gw, mask route.Addr) *route.RouteMessage {
	return &route.RouteMessage{Index: index, Flags: flags, Addrs: []route.Addr{dst, gw, mask}}
}

// A laptop on Wi-Fi with an exit node: the physical default goes through a
// router, so its gateway is an IP address and the route carries no link
// address; macOS also keeps a scoped default on another adapter, and NetBird
// splits the default on its own interface.
func TestUnderlayDefaultPicksThePhysicalDefault(t *testing.T) {
	ifaces := map[int]*net.Interface{
		4:  {Index: 4, Name: "en0"},
		7:  {Index: 7, Name: "en5"},
		20: {Index: 20, Name: "utun100"},
	}
	byIndex := func(i int) (*net.Interface, error) {
		if iface, ok := ifaces[i]; ok {
			return iface, nil
		}
		return nil, errors.New("no such interface")
	}

	up := unix.RTF_UP | unix.RTF_GATEWAY
	msgs := []route.Message{
		routeMsg(20, up, v4(0, 0, 0, 0), v4(100, 64, 0, 1), v4(128, 0, 0, 0)),
		routeMsg(20, up, v4(128, 0, 0, 0), v4(100, 64, 0, 1), v4(128, 0, 0, 0)),
		routeMsg(20, up, v4(0, 0, 0, 0), v4(100, 64, 0, 1), v4(0, 0, 0, 0)),
		routeMsg(7, up|unix.RTF_IFSCOPE, v4(0, 0, 0, 0), v4(10, 0, 0, 1), v4(0, 0, 0, 0)),
		routeMsg(4, up, v4(0, 0, 0, 0), v4(192, 168, 1, 1), v4(0, 0, 0, 0)),
	}

	nexthop, err := underlayDefault(msgs, netip.IPv4Unspecified(), "utun100", byIndex)
	require.NoError(t, err)
	require.NotNil(t, nexthop.Intf, "the physical default must carry its interface")
	assert.Equal(t, "en0", nexthop.Intf.Name, "default interface")
	assert.Equal(t, netip.MustParseAddr("192.168.1.1"), nexthop.IP, "default gateway")

	_, err = underlayDefault(msgs, netip.IPv6Unspecified(), "utun100", byIndex)
	assert.ErrorIs(t, err, vars.ErrRouteNotFound, "no IPv6 default in the table")
}
