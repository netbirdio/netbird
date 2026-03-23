//go:build linux && !android

package systemops

import (
	"fmt"
	"net"
	"net/netip"

	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

// getNextHopViaNetlink uses netlink.RouteGet() to determine the next hop for a destination IP.
// Unlike go-netroute which only reads the main routing table, netlink.RouteGet() asks the kernel
// to perform an actual routing decision, respecting policy routing rules (ip rule) and all tables.
// This is needed on devices like UniFi gateways where the default route lives in a separate
// policy routing table (e.g., 201.eth4) rather than in the main table.
func getNextHopViaNetlink(ip netip.Addr) (Nexthop, error) {
	dst := ip.AsSlice()
	routes, err := netlink.RouteGet(net.IP(dst))
	if err != nil {
		return Nexthop{}, fmt.Errorf("netlink.RouteGet(%s): %w", ip, err)
	}
	if len(routes) == 0 {
		return Nexthop{}, fmt.Errorf("no route to %s via netlink", ip)
	}

	route := routes[0]

	var intf *net.Interface
	if route.LinkIndex > 0 {
		intf, err = net.InterfaceByIndex(route.LinkIndex)
		if err != nil {
			log.Debugf("Failed to get interface for index %d: %v", route.LinkIndex, err)
		}
	}

	if route.Gw != nil {
		addr, err := ipToAddr(route.Gw, intf)
		if err != nil {
			return Nexthop{}, fmt.Errorf("convert gateway to address: %w", err)
		}
		log.Debugf("Policy routing fallback: route to %s via gw %s (table %d, iface %v)", ip, route.Gw, route.Table, intf)
		return Nexthop{IP: addr, Intf: intf}, nil
	}

	if route.Src != nil {
		addr, err := ipToAddr(route.Src, intf)
		if err != nil {
			return Nexthop{}, fmt.Errorf("convert source to address: %w", err)
		}
		log.Debugf("Policy routing fallback: route to %s via src %s (table %d, iface %v)", ip, route.Src, route.Table, intf)
		return Nexthop{IP: addr, Intf: intf}, nil
	}

	return Nexthop{Intf: intf}, nil
}
