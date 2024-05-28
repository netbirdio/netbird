package networkmonitor

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/routemanager"
)

const (
	unreachable = 0
	incomplete  = 1
	probe       = 2
	delay       = 3
	stale       = 4
	reachable   = 5
	permanent   = 6
	tbd         = 7
)

const interval = 10 * time.Second

func checkChange(ctx context.Context, nexthopv4 netip.Addr, intfv4 *net.Interface, nexthopv6 netip.Addr, intfv6 *net.Interface, callback func()) error {
	var neighborv4, neighborv6 *routemanager.Neighbor
	{
		initialNeighbors, err := getNeighbors()
		if err != nil {
			return fmt.Errorf("get neighbors: %w", err)
		}

		if n, ok := initialNeighbors[nexthopv4]; ok {
			neighborv4 = &n
		}
		if n, ok := initialNeighbors[nexthopv6]; ok {
			neighborv6 = &n
		}
	}
	log.Debugf("Network monitor: initial IPv4 neighbor: %v, IPv6 neighbor: %v", neighborv4, neighborv6)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ErrStopped
		case <-ticker.C:
			if changed(nexthopv4, intfv4, neighborv4, nexthopv6, intfv6, neighborv6) {
				go callback()
				return nil
			}
		}
	}
}

func changed(
	nexthopv4 netip.Addr,
	intfv4 *net.Interface,
	neighborv4 *routemanager.Neighbor,
	nexthopv6 netip.Addr,
	intfv6 *net.Interface,
	neighborv6 *routemanager.Neighbor,
) bool {
	neighbors, err := getNeighbors()
	if err != nil {
		log.Errorf("network monitor: error fetching current neighbors: %v", err)
		return false
	}
	if neighborChanged(nexthopv4, neighborv4, neighbors) || neighborChanged(nexthopv6, neighborv6, neighbors) {
		return true
	}

	routes, err := getRoutes()
	if err != nil {
		log.Errorf("network monitor: error fetching current routes: %v", err)
		return false
	}

	if routeChanged(nexthopv4, intfv4, routes) || routeChanged(nexthopv6, intfv6, routes) {
		return true
	}

	return false
}

// routeChanged checks if the default routes still point to our nexthop/interface
func routeChanged(nexthop netip.Addr, intf *net.Interface, routes map[netip.Prefix]routemanager.Route) bool {
	if !nexthop.IsValid() {
		return false
	}

	var unspec netip.Prefix
	if nexthop.Is6() {
		unspec = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	} else {
		unspec = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	}

	if r, ok := routes[unspec]; ok {
		if r.Nexthop != nexthop || compareIntf(r.Interface, intf) != 0 {
			intf := "<nil>"
			if r.Interface != nil {
				intf = r.Interface.Name
			}
			log.Infof("network monitor: default route changed: %s via %s (%s)", r.Destination, r.Nexthop, intf)
			return true
		}
	} else {
		log.Infof("network monitor: default route is gone")
		return true
	}

	return false

}

func neighborChanged(nexthop netip.Addr, neighbor *routemanager.Neighbor, neighbors map[netip.Addr]routemanager.Neighbor) bool {
	if neighbor == nil {
		return false
	}

	// TODO: consider non-local nexthops, e.g. on point-to-point interfaces
	if n, ok := neighbors[nexthop]; ok {
		if n.State != reachable && n.State != permanent {
			log.Infof("network monitor: neighbor %s (%s) is not reachable: %s", neighbor.IPAddress, neighbor.LinkLayerAddress, stateFromInt(n.State))
			return true
		} else if n.InterfaceIndex != neighbor.InterfaceIndex {
			log.Infof(
				"network monitor: neighbor %s (%s) changed interface from '%s' (%d) to '%s' (%d): %s",
				neighbor.IPAddress,
				neighbor.LinkLayerAddress,
				neighbor.InterfaceAlias,
				neighbor.InterfaceIndex,
				n.InterfaceAlias,
				n.InterfaceIndex,
				stateFromInt(n.State),
			)
			return true
		}
	} else {
		log.Infof("network monitor: neighbor %s (%s) is gone", neighbor.IPAddress, neighbor.LinkLayerAddress)
		return true
	}

	return false
}

func getNeighbors() (map[netip.Addr]routemanager.Neighbor, error) {
	entries, err := routemanager.GetNeighbors()
	if err != nil {
		return nil, fmt.Errorf("get neighbors: %w", err)
	}

	neighbours := make(map[netip.Addr]routemanager.Neighbor, len(entries))
	for _, entry := range entries {
		neighbours[entry.IPAddress] = entry
	}

	return neighbours, nil
}

func getRoutes() (map[netip.Prefix]routemanager.Route, error) {
	entries, err := routemanager.GetRoutes()
	if err != nil {
		return nil, fmt.Errorf("get routes: %w", err)
	}

	routes := make(map[netip.Prefix]routemanager.Route, len(entries))
	for _, entry := range entries {
		routes[entry.Destination] = entry
	}

	return routes, nil
}

func stateFromInt(state uint8) string {
	switch state {
	case unreachable:
		return "unreachable"
	case incomplete:
		return "incomplete"
	case probe:
		return "probe"
	case delay:
		return "delay"
	case stale:
		return "stale"
	case reachable:
		return "reachable"
	case permanent:
		return "permanent"
	case tbd:
		return "tbd"
	default:
		return "unknown"
	}
}

func compareIntf(a, b *net.Interface) int {
	if a == nil && b == nil {
		return 0
	}
	if a == nil {
		return -1
	}
	if b == nil {
		return 1
	}
	return a.Index - b.Index
}
