//go:build !android && !ios

package routemanager

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

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/iface"
	nbnet "github.com/netbirdio/netbird/util/net"
)

var splitDefaultv4_1 = netip.PrefixFrom(netip.IPv4Unspecified(), 1)
var splitDefaultv4_2 = netip.PrefixFrom(netip.AddrFrom4([4]byte{128}), 1)
var splitDefaultv6_1 = netip.PrefixFrom(netip.IPv6Unspecified(), 1)
var splitDefaultv6_2 = netip.PrefixFrom(netip.AddrFrom16([16]byte{0x80}), 1)

var ErrRouteNotFound = errors.New("route not found")
var ErrRouteNotAllowed = errors.New("route not allowed")

// TODO: fix: for default our wg address now appears as the default gw
func addRouteForCurrentDefaultGateway(prefix netip.Prefix) error {
	addr := netip.IPv4Unspecified()
	if prefix.Addr().Is6() {
		addr = netip.IPv6Unspecified()
	}

	defaultGateway, _, err := GetNextHop(addr)
	if err != nil && !errors.Is(err, ErrRouteNotFound) {
		return fmt.Errorf("get existing route gateway: %s", err)
	}

	if !prefix.Contains(defaultGateway) {
		log.Debugf("Skipping adding a new route for gateway %s because it is not in the network %s", defaultGateway, prefix)
		return nil
	}

	gatewayPrefix := netip.PrefixFrom(defaultGateway, 32)
	if defaultGateway.Is6() {
		gatewayPrefix = netip.PrefixFrom(defaultGateway, 128)
	}

	ok, err := existsInRouteTable(gatewayPrefix)
	if err != nil {
		return fmt.Errorf("unable to check if there is an existing route for gateway %s. error: %s", gatewayPrefix, err)
	}

	if ok {
		log.Debugf("Skipping adding a new route for gateway %s because it already exists", gatewayPrefix)
		return nil
	}

	gatewayHop, intf, err := GetNextHop(defaultGateway)
	if err != nil && !errors.Is(err, ErrRouteNotFound) {
		return fmt.Errorf("unable to get the next hop for the default gateway address. error: %s", err)
	}

	log.Debugf("Adding a new route for gateway %s with next hop %s", gatewayPrefix, gatewayHop)
	return addToRouteTable(gatewayPrefix, gatewayHop, intf)
}

func GetNextHop(ip netip.Addr) (netip.Addr, *net.Interface, error) {
	r, err := netroute.New()
	if err != nil {
		return netip.Addr{}, nil, fmt.Errorf("new netroute: %w", err)
	}
	intf, gateway, preferredSrc, err := r.Route(ip.AsSlice())
	if err != nil {
		log.Debugf("Failed to get route for %s: %v", ip, err)
		return netip.Addr{}, nil, ErrRouteNotFound
	}

	log.Debugf("Route for %s: interface %v nexthop %v, preferred source %v", ip, intf, gateway, preferredSrc)
	if gateway == nil {
		if preferredSrc == nil {
			return netip.Addr{}, nil, ErrRouteNotFound
		}
		log.Debugf("No next hop found for ip %s, using preferred source %s", ip, preferredSrc)

		addr, err := ipToAddr(preferredSrc, intf)
		if err != nil {
			return netip.Addr{}, nil, fmt.Errorf("convert preferred source to address: %w", err)
		}
		return addr.Unmap(), intf, nil
	}

	addr, err := ipToAddr(gateway, intf)
	if err != nil {
		return netip.Addr{}, nil, fmt.Errorf("convert gateway to address: %w", err)
	}

	return addr, intf, nil
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

	linkLocalPrefix, err := netip.ParsePrefix("fe80::/10")
	if err != nil {
		return false, err
	}
	if prefix.Addr().Is6() && linkLocalPrefix.Contains(prefix.Addr()) {
		// The link local prefix is not explicitly part of the routing table, but should be considered as such.
		return true, nil
	}

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
		if tableRoute.Bits() > minRangeBits && tableRoute.Contains(prefix.Addr()) && tableRoute.Bits() < prefix.Bits() {
			return true, nil
		}
	}
	return false, nil
}

// addRouteToNonVPNIntf adds a new route to the routing table for the given prefix and returns the next hop and interface.
// If the next hop or interface is pointing to the VPN interface, it will return the initial values.
func addRouteToNonVPNIntf(prefix netip.Prefix, vpnIntf *iface.WGIface, initialNextHop netip.Addr, initialIntf *net.Interface) (netip.Addr, *net.Interface, error) {
	addr := prefix.Addr()
	switch {
	case addr.IsLoopback(),
		addr.IsLinkLocalUnicast(),
		addr.IsLinkLocalMulticast(),
		addr.IsInterfaceLocalMulticast(),
		addr.IsUnspecified(),
		addr.IsMulticast():

		return netip.Addr{}, nil, ErrRouteNotAllowed
	}

	// Determine the exit interface and next hop for the prefix, so we can add a specific route
	nexthop, intf, err := GetNextHop(addr)
	if err != nil {
		return netip.Addr{}, nil, fmt.Errorf("get next hop: %w", err)
	}

	log.Debugf("Found next hop %s for prefix %s with interface %v", nexthop, prefix, intf)
	exitNextHop := nexthop
	exitIntf := intf

	vpnAddr, ok := netip.AddrFromSlice(vpnIntf.Address().IP)
	if !ok {
		return netip.Addr{}, nil, fmt.Errorf("failed to convert vpn address to netip.Addr")
	}

	// if next hop is the VPN address or the interface is the VPN interface, we should use the initial values
	if exitNextHop == vpnAddr || exitIntf != nil && exitIntf.Name == vpnIntf.Name() {
		log.Debugf("Route for prefix %s is pointing to the VPN interface", prefix)
		exitNextHop = initialNextHop
		exitIntf = initialIntf
	}

	log.Debugf("Adding a new route for prefix %s with next hop %s", prefix, exitNextHop)
	if err := addToRouteTable(prefix, exitNextHop, exitIntf); err != nil {
		return netip.Addr{}, nil, fmt.Errorf("add route to table: %w", err)
	}

	return exitNextHop, exitIntf, nil
}

// genericAddVPNRoute adds a new route to the vpn interface, it splits the default prefix
// in two /1 prefixes to avoid replacing the existing default route
func genericAddVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	if prefix == defaultv4 {
		if err := addToRouteTable(splitDefaultv4_1, netip.Addr{}, intf); err != nil {
			return err
		}
		if err := addToRouteTable(splitDefaultv4_2, netip.Addr{}, intf); err != nil {
			if err2 := removeFromRouteTable(splitDefaultv4_1, netip.Addr{}, intf); err2 != nil {
				log.Warnf("Failed to rollback route addition: %s", err2)
			}
			return err
		}

		// TODO: remove once IPv6 is supported on the interface
		if err := addToRouteTable(splitDefaultv6_1, netip.Addr{}, intf); err != nil {
			return fmt.Errorf("add unreachable route split 1: %w", err)
		}
		if err := addToRouteTable(splitDefaultv6_2, netip.Addr{}, intf); err != nil {
			if err2 := removeFromRouteTable(splitDefaultv6_1, netip.Addr{}, intf); err2 != nil {
				log.Warnf("Failed to rollback route addition: %s", err2)
			}
			return fmt.Errorf("add unreachable route split 2: %w", err)
		}

		return nil
	} else if prefix == defaultv6 {
		if err := addToRouteTable(splitDefaultv6_1, netip.Addr{}, intf); err != nil {
			return fmt.Errorf("add unreachable route split 1: %w", err)
		}
		if err := addToRouteTable(splitDefaultv6_2, netip.Addr{}, intf); err != nil {
			if err2 := removeFromRouteTable(splitDefaultv6_1, netip.Addr{}, intf); err2 != nil {
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

	return addToRouteTable(prefix, netip.Addr{}, intf)
}

// genericRemoveVPNRoute removes the route from the vpn interface. If a default prefix is given,
// it will remove the split /1 prefixes
func genericRemoveVPNRoute(prefix netip.Prefix, intf *net.Interface) error {
	if prefix == defaultv4 {
		var result *multierror.Error
		if err := removeFromRouteTable(splitDefaultv4_1, netip.Addr{}, intf); err != nil {
			result = multierror.Append(result, err)
		}
		if err := removeFromRouteTable(splitDefaultv4_2, netip.Addr{}, intf); err != nil {
			result = multierror.Append(result, err)
		}

		// TODO: remove once IPv6 is supported on the interface
		if err := removeFromRouteTable(splitDefaultv6_1, netip.Addr{}, intf); err != nil {
			result = multierror.Append(result, err)
		}
		if err := removeFromRouteTable(splitDefaultv6_2, netip.Addr{}, intf); err != nil {
			result = multierror.Append(result, err)
		}

		return result.ErrorOrNil()
	} else if prefix == defaultv6 {
		var result *multierror.Error
		if err := removeFromRouteTable(splitDefaultv6_1, netip.Addr{}, intf); err != nil {
			result = multierror.Append(result, err)
		}
		if err := removeFromRouteTable(splitDefaultv6_2, netip.Addr{}, intf); err != nil {
			result = multierror.Append(result, err)
		}

		return result.ErrorOrNil()
	}

	return removeFromRouteTable(prefix, netip.Addr{}, intf)
}

func getPrefixFromIP(ip net.IP) (*netip.Prefix, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil, fmt.Errorf("parse IP address: %s", ip)
	}
	addr = addr.Unmap()

	var prefixLength int
	switch {
	case addr.Is4():
		prefixLength = 32
	case addr.Is6():
		prefixLength = 128
	default:
		return nil, fmt.Errorf("invalid IP address: %s", addr)
	}

	prefix := netip.PrefixFrom(addr, prefixLength)
	return &prefix, nil
}

func setupRoutingWithRouteManager(routeManager **RouteManager, initAddresses []net.IP, wgIface *iface.WGIface) (peer.BeforeAddPeerHookFunc, peer.AfterRemovePeerHookFunc, error) {
	initialNextHopV4, initialIntfV4, err := GetNextHop(netip.IPv4Unspecified())
	if err != nil && !errors.Is(err, ErrRouteNotFound) {
		log.Errorf("Unable to get initial v4 default next hop: %v", err)
	}
	initialNextHopV6, initialIntfV6, err := GetNextHop(netip.IPv6Unspecified())
	if err != nil && !errors.Is(err, ErrRouteNotFound) {
		log.Errorf("Unable to get initial v6 default next hop: %v", err)
	}

	*routeManager = NewRouteManager(
		func(prefix netip.Prefix) (netip.Addr, *net.Interface, error) {
			addr := prefix.Addr()
			nexthop, intf := initialNextHopV4, initialIntfV4
			if addr.Is6() {
				nexthop, intf = initialNextHopV6, initialIntfV6
			}
			return addRouteToNonVPNIntf(prefix, wgIface, nexthop, intf)
		},
		removeFromRouteTable,
	)

	return setupHooks(*routeManager, initAddresses)
}

func cleanupRoutingWithRouteManager(routeManager *RouteManager) error {
	if routeManager == nil {
		return nil
	}

	// TODO: Remove hooks selectively
	nbnet.RemoveDialerHooks()
	nbnet.RemoveListenerHooks()

	if err := routeManager.Flush(); err != nil {
		return fmt.Errorf("flush route manager: %w", err)
	}

	return nil
}

func setupHooks(routeManager *RouteManager, initAddresses []net.IP) (peer.BeforeAddPeerHookFunc, peer.AfterRemovePeerHookFunc, error) {
	beforeHook := func(connID nbnet.ConnectionID, ip net.IP) error {
		prefix, err := getPrefixFromIP(ip)
		if err != nil {
			return fmt.Errorf("convert ip to prefix: %w", err)
		}

		if err := routeManager.AddRouteRef(connID, *prefix); err != nil {
			return fmt.Errorf("adding route reference: %v", err)
		}

		return nil
	}
	afterHook := func(connID nbnet.ConnectionID) error {
		if err := routeManager.RemoveRouteRef(connID); err != nil {
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
		return result.ErrorOrNil()
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
