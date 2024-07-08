package networkmonitor

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
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

func checkChange(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop, callback func()) error {
	var neighborv4, neighborv6 *systemops.Neighbor
	{
		initialNeighbors, err := getNeighbors()
		if err != nil {
			return fmt.Errorf("get neighbors: %w", err)
		}

		neighborv4 = assignNeighbor(nexthopv4, initialNeighbors)
		neighborv6 = assignNeighbor(nexthopv6, initialNeighbors)
	}
	log.Debugf("Network monitor: initial IPv4 neighbor: %v, IPv6 neighbor: %v", neighborv4, neighborv6)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ErrStopped
		case <-ticker.C:
			if changed(nexthopv4, neighborv4, nexthopv6, neighborv6) {
				go callback()
				return nil
			}
		}
	}
}

func assignNeighbor(nexthop systemops.Nexthop, initialNeighbors map[netip.Addr]systemops.Neighbor) *systemops.Neighbor {
	if n, ok := initialNeighbors[nexthop.IP]; ok &&
		n.State != unreachable &&
		n.State != incomplete &&
		n.State != tbd {
		return &n
	}
	return nil
}

func changed(
	nexthopv4 systemops.Nexthop,
	neighborv4 *systemops.Neighbor,
	nexthopv6 systemops.Nexthop,
	neighborv6 *systemops.Neighbor,
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

	if routeChanged(nexthopv4, nexthopv4.Intf, routes) || routeChanged(nexthopv6, nexthopv6.Intf, routes) {
		return true
	}

	return false
}

// routeChanged checks if the default routes still point to our nexthop/interface
func routeChanged(nexthop systemops.Nexthop, intf *net.Interface, routes []systemops.Route) bool {
	if !nexthop.IP.IsValid() {
		return false
	}

	unspec := getUnspecifiedPrefix(nexthop.IP)
	defaultRoutes, foundMatchingRoute := processRoutes(nexthop, intf, routes, unspec)

	log.Tracef("network monitor: all default routes:\n%s", strings.Join(defaultRoutes, "\n"))

	if !foundMatchingRoute {
		logRouteChange(nexthop.IP, intf)
		return true
	}

	return false
}

func getUnspecifiedPrefix(ip netip.Addr) netip.Prefix {
	if ip.Is6() {
		return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
}

func processRoutes(nexthop systemops.Nexthop, intf *net.Interface, routes []systemops.Route, unspec netip.Prefix) ([]string, bool) {
	var defaultRoutes []string
	foundMatchingRoute := false

	for _, r := range routes {
		if r.Destination == unspec {
			routeInfo := formatRouteInfo(r)
			defaultRoutes = append(defaultRoutes, routeInfo)

			if r.Nexthop == nexthop.IP && compareIntf(r.Interface, intf) == 0 {
				foundMatchingRoute = true
				log.Debugf("network monitor: found matching default route: %s", routeInfo)
			}
		}
	}

	return defaultRoutes, foundMatchingRoute
}

func formatRouteInfo(r systemops.Route) string {
	newIntf := "<nil>"
	if r.Interface != nil {
		newIntf = r.Interface.Name
	}
	return fmt.Sprintf("Nexthop: %s, Interface: %s", r.Nexthop, newIntf)
}

func logRouteChange(ip netip.Addr, intf *net.Interface) {
	oldIntf := "<nil>"
	if intf != nil {
		oldIntf = intf.Name
	}
	log.Infof("network monitor: default route for %s (%s) is gone or changed", ip, oldIntf)
}

func neighborChanged(nexthop systemops.Nexthop, neighbor *systemops.Neighbor, neighbors map[netip.Addr]systemops.Neighbor) bool {
	if neighbor == nil {
		return false
	}

	// TODO: consider non-local nexthops, e.g. on point-to-point interfaces
	if n, ok := neighbors[nexthop.IP]; ok {
		if n.State == unreachable || n.State == incomplete {
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

func getNeighbors() (map[netip.Addr]systemops.Neighbor, error) {
	entries, err := systemops.GetNeighbors()
	if err != nil {
		return nil, fmt.Errorf("get neighbors: %w", err)
	}

	neighbours := make(map[netip.Addr]systemops.Neighbor, len(entries))
	for _, entry := range entries {
		neighbours[entry.IPAddress] = entry
	}

	return neighbours, nil
}

func getRoutes() ([]systemops.Route, error) {
	entries, err := systemops.GetRoutes()
	if err != nil {
		return nil, fmt.Errorf("get routes: %w", err)
	}

	return entries, nil
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
