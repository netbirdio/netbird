package systemops

import (
	"net"
	"net/netip"

	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/iface"
)

type Nexthop struct {
	IP   netip.Addr
	Intf *net.Interface
}

type ExclusionCounter = refcounter.Counter[any, Nexthop]

var splitDefaultv4_1 = netip.PrefixFrom(netip.IPv4Unspecified(), 1)
var splitDefaultv4_2 = netip.PrefixFrom(netip.AddrFrom4([4]byte{128}), 1)
var splitDefaultv6_1 = netip.PrefixFrom(netip.IPv6Unspecified(), 1)
var splitDefaultv6_2 = netip.PrefixFrom(netip.AddrFrom16([16]byte{0x80}), 1)

type SysOps struct {
	refCounter  *ExclusionCounter
	wgInterface *iface.WGIface
}

func NewSysOps(wgInterface *iface.WGIface) *SysOps {
	return &SysOps{
		wgInterface: wgInterface,
	}
}

// TODO: fix: for default our wg address now appears as the default gw
func addRouteForCurrentDefaultGateway(prefix netip.Prefix) error {
	addr := netip.IPv4Unspecified()
	if prefix.Addr().Is6() {
		addr = netip.IPv6Unspecified()
	}

	nexthop, err := GetNextHop(addr)
	if err != nil && !errors.Is(err, vars.ErrRouteNotFound) {
		return fmt.Errorf("get existing route gateway: %s", err)
	}

	if !prefix.Contains(nexthop.IP) {
		log.Debugf("Skipping adding a new route for gateway %s because it is not in the network %s", nexthop.IP, prefix)
		return nil
	}

	gatewayPrefix := netip.PrefixFrom(nexthop.IP, 32)
	if nexthop.IP.Is6() {
		gatewayPrefix = netip.PrefixFrom(nexthop.IP, 128)
	}

	ok, err := existsInRouteTable(gatewayPrefix)
	if err != nil {
		return fmt.Errorf("unable to check if there is an existing route for gateway %s. error: %s", gatewayPrefix, err)
	}

	if ok {
		log.Debugf("Skipping adding a new route for gateway %s because it already exists", gatewayPrefix)
		return nil
	}

	nexthop, err = GetNextHop(nexthop.IP)
	if err != nil && !errors.Is(err, vars.ErrRouteNotFound) {
		return fmt.Errorf("unable to get the next hop for the default gateway address. error: %s", err)
	}

	log.Debugf("Adding a new route for gateway %s with next hop %s", gatewayPrefix, nexthop.IP)
	return addToRouteTable(gatewayPrefix, nexthop)
}

func GetNextHop(ip netip.Addr) (Nexthop, error) {
	r, err := netroute.New()
	if err != nil {
		return Nexthop{}, fmt.Errorf("new netroute: %w", err)
	}
	intf, gateway, preferredSrc, err := r.Route(ip.AsSlice())
	if err != nil {
		log.Debugf("Failed to get route for %s: %v", ip, err)
		return Nexthop{}, vars.ErrRouteNotFound
	}

	log.Debugf("Route for %s: interface %v nexthop %v, preferred source %v", ip, intf, gateway, preferredSrc)
	if gateway == nil {
		if runtime.GOOS == "freebsd" {
			return Nexthop{Intf: intf}, nil
		}

		if preferredSrc == nil {
			return Nexthop{}, vars.ErrRouteNotFound
		}
		log.Debugf("No next hop found for IP %s, using preferred source %s", ip, preferredSrc)

		addr, err := ipToAddr(preferredSrc, intf)
		if err != nil {
			return Nexthop{}, fmt.Errorf("convert preferred source to address: %w", err)
		}
		return Nexthop{
			IP:   addr.Unmap(),
			Intf: intf,
		}, nil
	}

	addr, err := ipToAddr(gateway, intf)
	if err != nil {
		return Nexthop{}, fmt.Errorf("convert gateway to address: %w", err)
	}

	return Nexthop{
		IP:   addr,
		Intf: intf,
	}, nil
}

// converts a net.IP to a netip.Addr including the zone based on the passed interface
func ipToAddr(ip net.IP, intf *net.Interface) (netip.Addr, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, fmt.Errorf("failed to convert IP address to netip.Addr: %s", ip)
	}

	if intf != nil && (addr.IsLinkLocalMulticast() || addr.IsLinkLocalUnicast()) {
		log.Tracef("Adding zone %s to address %s", intf.Name, addr)
		if runtime.GOOS == "windows" {
			addr = addr.WithZone(strconv.Itoa(intf.Index))
		} else {
			addr = addr.WithZone(intf.Name)
		}
	}

	return addr.Unmap(), nil
}

func existsInRouteTable(prefix netip.Prefix) (bool, error) {
	routes, err := getRoutesFromTable()
	if err != nil {
		return false, fmt.Errorf("get routes from table: %w", err)
	}
	for _, tableRoute := range routes {
		if tableRoute == prefix {
			return true, nil
		}
	}
	return false, nil
}

func isSubRange(prefix netip.Prefix) (bool, error) {
	routes, err := getRoutesFromTable()
	if err != nil {
		return false, fmt.Errorf("get routes from table: %w", err)
	}
	for _, tableRoute := range routes {
		if tableRoute.Bits() > vars.MinRangeBits && tableRoute.Contains(prefix.Addr()) && tableRoute.Bits() < prefix.Bits() {
			return true, nil
		}
	}
	return false, nil
}

// addRouteToNonVPNIntf adds a new route to the routing table for the given prefix and returns the next hop and interface.
// If the next hop or interface is pointing to the VPN interface, it will return the initial values.
func addRouteToNonVPNIntf(prefix netip.Prefix, vpnIntf *iface.WGIface, initialNextHop Nexthop) (Nexthop, error) {
	addr := prefix.Addr()
	switch {
	case addr.IsLoopback(),
		addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(),
		addr.IsInterfaceLocalMulticast(),
		addr.IsUnspecified(),
		addr.IsMulticast():

		return Nexthop{}, vars.ErrRouteNotAllowed
	}

	// Determine the exit interface and next hop for the prefix, so we can add a specific route
	nexthop, err := GetNextHop(addr)
	if err != nil {
		return Nexthop{}, fmt.Errorf("get next hop: %w", err)
	}

	log.Debugf("Found next hop %s for prefix %s with interface %v", nexthop.IP, prefix, nexthop.IP)
	exitNextHop := Nexthop{
		IP:   nexthop.IP,
		Intf: nexthop.Intf,
	}

	vpnAddr, ok := netip.AddrFromSlice(vpnIntf.Address().IP)
	if !ok {
		return Nexthop{}, fmt.Errorf("failed to convert vpn address to netip.Addr")
	}

	// if next hop is the VPN address or the interface is the VPN interface, we should use the initial values
	if exitNextHop.IP == vpnAddr || exitNextHop.Intf != nil && exitNextHop.Intf.Name == vpnIntf.Name() {
		log.Debugf("Route for prefix %s is pointing to the VPN interface", prefix)
		exitNextHop = initialNextHop
	}

	log.Debugf("Adding a new route for prefix %s with next hop %s", prefix, exitNextHop.IP)
	if err := addToRouteTable(prefix, exitNextHop); err != nil {
		return Nexthop{}, fmt.Errorf("add route to table: %w", err)
	}

	return exitNextHop, nil
}

// genericAddVPNRoute adds a new route to the vpn interface, it splits the default prefix
// in two /1 prefixes to avoid replacing the existing default route
func genericAddVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	nextHop := Nexthop{netip.Addr{}, intf}

	if prefix == vars.Defaultv4 {
		if err := addToRouteTable(splitDefaultv4_1, nextHop); err != nil {
			return err
		}
		if err := addToRouteTable(splitDefaultv4_2, nextHop); err != nil {
			if err2 := removeFromRouteTable(splitDefaultv4_1, nextHop); err2 != nil {
				log.Warnf("Failed to rollback route addition: %s", err2)
			}
			return err
		}

		// TODO: remove once IPv6 is supported on the interface
		if err := addToRouteTable(splitDefaultv6_1, nextHop); err != nil {
			return fmt.Errorf("add unreachable route split 1: %w", err)
		}
		if err := addToRouteTable(splitDefaultv6_2, nextHop); err != nil {
			if err2 := removeFromRouteTable(splitDefaultv6_1, nextHop); err2 != nil {
				log.Warnf("Failed to rollback route addition: %s", err2)
			}
			return fmt.Errorf("add unreachable route split 2: %w", err)
		}

		return nil
	} else if prefix == vars.Defaultv6 {
		if err := addToRouteTable(splitDefaultv6_1, nextHop); err != nil {
			return fmt.Errorf("add unreachable route split 1: %w", err)
		}
		if err := addToRouteTable(splitDefaultv6_2, nextHop); err != nil {
			if err2 := removeFromRouteTable(splitDefaultv6_1, nextHop); err2 != nil {
				log.Warnf("Failed to rollback route addition: %s", err2)
			}
			return fmt.Errorf("add unreachable route split 2: %w", err)
		}

		return nil
	}

	return addNonExistingRoute(prefix, intf)
}

// addNonExistingRoute adds a new route to the vpn interface if it doesn't exist in the current routing table
func addNonExistingRoute(prefix netip.Prefix, intf *net.Interface) error {
	ok, err := existsInRouteTable(prefix)
	if err != nil {
		return fmt.Errorf("exists in route table: %w", err)
	}
	if ok {
		log.Warnf("Skipping adding a new route for network %s because it already exists", prefix)
		return nil
	}

	ok, err = isSubRange(prefix)
	if err != nil {
		return fmt.Errorf("sub range: %w", err)
	}

	if ok {
		err := addRouteForCurrentDefaultGateway(prefix)
		if err != nil {
			log.Warnf("Unable to add route for current default gateway route. Will proceed without it. error: %s", err)
		}
	}
}
