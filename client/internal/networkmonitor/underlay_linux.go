//go:build !android

package networkmonitor

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
	nbnet "github.com/netbirdio/netbird/client/net"
)

// underlayNextHop resolves the default next hop as NetBird's own control
// traffic sees it. The lookup carries the control plane fwmark, which skips
// the NetBird routing table, so an exit node does not hide the physical
// default behind the NetBird interface.
func underlayNextHop(family netip.Addr) (systemops.Nexthop, error) {
	if !nbnet.AdvancedRouting() {
		return systemops.GetNextHop(family)
	}

	// The kernel rejects lookups for an unspecified destination; any address
	// that only the default route covers resolves the same way.
	probe := netip.AddrFrom4([4]byte{0, 0, 0, 1})
	if family.Is6() {
		probe = netip.AddrFrom16([16]byte{15: 2})
	}

	routes, err := netlink.RouteGetWithOptions(probe.AsSlice(), &netlink.RouteGetOptions{Mark: nbnet.ControlPlaneMark})
	if errors.Is(err, unix.ENETUNREACH) || err == nil && len(routes) == 0 {
		return systemops.Nexthop{}, vars.ErrRouteNotFound
	}
	if err != nil {
		return systemops.Nexthop{}, fmt.Errorf("route get with the control plane mark: %w", err)
	}

	intf, err := net.InterfaceByIndex(routes[0].LinkIndex)
	if err != nil {
		return systemops.Nexthop{}, fmt.Errorf("interface %d: %w", routes[0].LinkIndex, err)
	}

	gw, ok := netip.AddrFromSlice(routes[0].Gw)
	if !ok {
		// On-link default: no gateway, the interface alone identifies the hop.
		return systemops.Nexthop{Intf: intf}, nil
	}
	return systemops.Nexthop{IP: gw.Unmap(), Intf: intf}, nil
}
