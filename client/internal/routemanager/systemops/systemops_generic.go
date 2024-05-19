//go:build !android && !ios

package systemops

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"strconv"

	"github.com/hashicorp/go-multierror"
	"github.com/libp2p/go-netroute"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/client/internal/routemanager/util"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
	"github.com/netbirdio/netbird/iface"
	nbnet "github.com/netbirdio/netbird/util/net"
)

var splitDefaultv4_1 = netip.PrefixFrom(netip.IPv4Unspecified(), 1)
var splitDefaultv4_2 = netip.PrefixFrom(netip.AddrFrom4([4]byte{128}), 1)
var splitDefaultv6_1 = netip.PrefixFrom(netip.IPv6Unspecified(), 1)
var splitDefaultv6_2 = netip.PrefixFrom(netip.AddrFrom16([16]byte{0x80}), 1)

func (r *RoutingManager) setupRefCounter(initAddresses []net.IP) (peer.BeforeAddPeerHookFunc, peer.AfterRemovePeerHookFunc, error) {
	initialNextHopV4, err := GetNextHop(netip.IPv4Unspecified())
	if err != nil && !errors.Is(err, vars.ErrRouteNotFound) {
		log.Errorf("Unable to get initial v4 default next hop: %v", err)
	}
	initialNextHopV6, err := GetNextHop(netip.IPv6Unspecified())
	if err != nil && !errors.Is(err, vars.ErrRouteNotFound) {
		log.Errorf("Unable to get initial v6 default next hop: %v", err)
	}

	refCounter := refcounter.New(
		func(prefix netip.Prefix, _ any) (Nexthop, error) {
			initialNexthop := initialNextHopV4
			if prefix.Addr().Is6() {
				initialNexthop = initialNextHopV6
			}

			nexthop, err := r.addRouteToNonVPNIntf(prefix, r.wgInterface, initialNexthop)
			if errors.Is(err, vars.ErrRouteNotAllowed) || errors.Is(err, vars.ErrRouteNotFound) {
				log.Tracef("Adding for prefix %s: %v", prefix, err)
				// These errors are not critical but also we should not track and try to remove the routes either.
				return nexthop, refcounter.ErrIgnore
			}
			return nexthop, err
		},
		r.removeFromRouteTable,
	)

	r.refCounter = refCounter

	return r.setupHooks(initAddresses)
}

func (r *RoutingManager) cleanupRefCounter() error {
	if r.refCounter == nil {
		return nil
	}

	// TODO: Remove hooks selectively
	nbnet.RemoveDialerHooks()
	nbnet.RemoveListenerHooks()

	if err := r.refCounter.Flush(); err != nil {
		return fmt.Errorf("flush route manager: %w", err)
	}

	return nil
}

// TODO: fix: for default our wg address now appears as the default gw
func (r *RoutingManager) addRouteForCurrentDefaultGateway(prefix netip.Prefix) error {
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
	return r.addToRouteTable(gatewayPrefix, nexthop)
}

// addRouteToNonVPNIntf adds a new route to the routing table for the given prefix and returns the next hop and interface.
// If the next hop or interface is pointing to the VPN interface, it will return the initial values.
func (r *RoutingManager) addRouteToNonVPNIntf(prefix netip.Prefix, vpnIntf *iface.WGIface, initialNextHop Nexthop) (Nexthop, error) {
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
	if err := r.addToRouteTable(prefix, exitNextHop); err != nil {
		return Nexthop{}, fmt.Errorf("add route to table: %w", err)
	}

	return exitNextHop, nil
}

// genericAddVPNRoute adds a new route to the vpn interface, it splits the default prefix
// in two /1 prefixes to avoid replacing the existing default route
func (r *RoutingManager) genericAddVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	nextHop := Nexthop{netip.Addr{}, intf}

	if prefix == vars.Defaultv4 {
		if err := r.addToRouteTable(splitDefaultv4_1, nextHop); err != nil {
			return err
		}
		if err := r.addToRouteTable(splitDefaultv4_2, nextHop); err != nil {
			if err2 := r.removeFromRouteTable(splitDefaultv4_1, nextHop); err2 != nil {
				log.Warnf("Failed to rollback route addition: %s", err2)
			}
			return err
		}

		// TODO: remove once IPv6 is supported on the interface
		if err := r.addToRouteTable(splitDefaultv6_1, nextHop); err != nil {
			return fmt.Errorf("add unreachable route split 1: %w", err)
		}
		if err := r.addToRouteTable(splitDefaultv6_2, nextHop); err != nil {
			if err2 := r.removeFromRouteTable(splitDefaultv6_1, nextHop); err2 != nil {
				log.Warnf("Failed to rollback route addition: %s", err2)
			}
			return fmt.Errorf("add unreachable route split 2: %w", err)
		}

		return nil
	} else if prefix == vars.Defaultv6 {
		if err := r.addToRouteTable(splitDefaultv6_1, nextHop); err != nil {
			return fmt.Errorf("add unreachable route split 1: %w", err)
		}
		if err := r.addToRouteTable(splitDefaultv6_2, nextHop); err != nil {
			if err2 := r.removeFromRouteTable(splitDefaultv6_1, nextHop); err2 != nil {
				log.Warnf("Failed to rollback route addition: %s", err2)
			}
			return fmt.Errorf("add unreachable route split 2: %w", err)
		}

		return nil
	}

	return r.addNonExistingRoute(prefix, intf)
}

// addNonExistingRoute adds a new route to the vpn interface if it doesn't exist in the current routing table
func (r *RoutingManager) addNonExistingRoute(prefix netip.Prefix, intf *net.Interface) error {
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
		if err := r.addRouteForCurrentDefaultGateway(prefix); err != nil {
			log.Warnf("Unable to add route for current default gateway route. Will proceed without it. error: %s", err)
		}
	}

	return r.addToRouteTable(prefix, Nexthop{netip.Addr{}, intf})
}

// genericRemoveVPNRoute removes the route from the vpn interface. If a default prefix is given,
// it will remove the split /1 prefixes
func (r *RoutingManager) genericRemoveVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	nextHop := Nexthop{netip.Addr{}, intf}

	if prefix == vars.Defaultv4 {
		var result *multierror.Error
		if err := r.removeFromRouteTable(splitDefaultv4_1, nextHop); err != nil {
			result = multierror.Append(result, err)
		}
		if err := r.removeFromRouteTable(splitDefaultv4_2, nextHop); err != nil {
			result = multierror.Append(result, err)
		}

		// TODO: remove once IPv6 is supported on the interface
		if err := r.removeFromRouteTable(splitDefaultv6_1, nextHop); err != nil {
			result = multierror.Append(result, err)
		}
		if err := r.removeFromRouteTable(splitDefaultv6_2, nextHop); err != nil {
			result = multierror.Append(result, err)
		}

		return nberrors.FormatErrorOrNil(result)
	} else if prefix == vars.Defaultv6 {
		var result *multierror.Error
		if err := r.removeFromRouteTable(splitDefaultv6_1, nextHop); err != nil {
			result = multierror.Append(result, err)
		}
		if err := r.removeFromRouteTable(splitDefaultv6_2, nextHop); err != nil {
			result = multierror.Append(result, err)
		}

		return nberrors.FormatErrorOrNil(result)
	}

	return r.removeFromRouteTable(prefix, nextHop)
}

func (r *RoutingManager) setupHooks(initAddresses []net.IP) (peer.BeforeAddPeerHookFunc, peer.AfterRemovePeerHookFunc, error) {
	beforeHook := func(connID nbnet.ConnectionID, ip net.IP) error {
		prefix, err := util.GetPrefixFromIP(ip)
		if err != nil {
			return fmt.Errorf("convert ip to prefix: %w", err)
		}

		if _, err := r.refCounter.IncrementWithID(string(connID), prefix, nil); err != nil {
			return fmt.Errorf("adding route reference: %v", err)
		}

		return nil
	}
	afterHook := func(connID nbnet.ConnectionID) error {
		if err := r.refCounter.DecrementWithID(string(connID)); err != nil {
			return fmt.Errorf("remove route reference: %w", err)
		}

		return nil
	}

	for _, ip := range initAddresses {
		if err := beforeHook("init", ip); err != nil {
			log.Errorf("Failed to add route reference: %v", err)
		}
	}

	nbnet.AddDialerHook(func(ctx context.Context, connID nbnet.ConnectionID, resolvedIPs []net.IPAddr) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		var result *multierror.Error
		for _, ip := range resolvedIPs {
			result = multierror.Append(result, beforeHook(connID, ip.IP))
		}
		return nberrors.FormatErrorOrNil(result)
	})

	nbnet.AddDialerCloseHook(func(connID nbnet.ConnectionID, conn *net.Conn) error {
		return afterHook(connID)
	})

	nbnet.AddListenerWriteHook(func(connID nbnet.ConnectionID, ip *net.IPAddr, data []byte) error {
		return beforeHook(connID, ip.IP)
	})

	nbnet.AddListenerCloseHook(func(connID nbnet.ConnectionID, conn net.PacketConn) error {
		return afterHook(connID)
	})

	return beforeHook, afterHook, nil
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
