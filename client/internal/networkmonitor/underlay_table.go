//go:build windows || (darwin && !ios)

package networkmonitor

import (
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
	nbnet "github.com/netbirdio/netbird/client/net"
)

// underlayNextHop resolves the default next hop of the physical network from
// the routing table, skipping the NetBird interface, so an exit node does not
// hide the physical default behind its split routes.
func underlayNextHop(family netip.Addr) (systemops.Nexthop, error) {
	if !nbnet.AdvancedRouting() {
		return systemops.GetNextHop(family)
	}
	return systemops.GetUnderlayNextHop(family, nbnet.GetVPNInterfaceName())
}
