//go:build windows

package routemanager

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"
	"github.com/yusufpapurcu/wmi"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/iface"
	nbnet "github.com/netbirdio/netbird/util/net"
)

type Win32_IP4RouteTable struct {
	Destination string
	Mask        string
}

var splitDefaultv4_1 = netip.PrefixFrom(netip.IPv4Unspecified(), 1)
var splitDefaultv4_2 = netip.PrefixFrom(netip.AddrFrom4([4]byte{128}), 1)
var splitDefaultv6_1 = netip.PrefixFrom(netip.IPv6Unspecified(), 1)
var splitDefaultv6_2 = netip.PrefixFrom(netip.AddrFrom16([16]byte{0x80}), 1)

var routeManager *RouteManager

func setupRouting(initAddresses []net.IP, wgIface *iface.WGIface) (peer.BeforeAddPeerHookFunc, peer.AfterRemovePeerHookFunc, error) {
	intialNextHop, initialIntf, err := getNextHop(netip.IPv4Unspecified())
	if err != nil {
		log.Errorf("Unable to get initial default next hop: %v", err)
	}

	routeManager = NewRouteManager(
		func(prefix netip.Prefix) error {
			return addRouteToNonVPNIntf(prefix, wgIface, intialNextHop, initialIntf)
		},
		func(prefix netip.Prefix) error {
			return removeFromRouteTableIfNonSystem(prefix, "", "")
		},
	)

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

	nbnet.AddDialHook(func(ctx context.Context, connID nbnet.ConnectionID, resolvedIPs []net.IPAddr) error {
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

func cleanupRouting() error {
	if routeManager == nil {
		return nil
	}

	if err := routeManager.Flush(); err != nil {
		return fmt.Errorf("flush route manager: %w", err)
	}

	return nil
}

func getRoutesFromTable() ([]netip.Prefix, error) {
	var routes []Win32_IP4RouteTable
	query := "SELECT Destination, Mask FROM Win32_IP4RouteTable"

	err := wmi.Query(query, &routes)
	if err != nil {
		return nil, fmt.Errorf("get routes: %w", err)
	}

	var prefixList []netip.Prefix
	for _, route := range routes {
		addr, err := netip.ParseAddr(route.Destination)
		if err != nil {
			log.Warnf("Unable to parse route destination %s: %v", route.Destination, err)
			continue
		}
		maskSlice := net.ParseIP(route.Mask).To4()
		if maskSlice == nil {
			log.Warnf("Unable to parse route mask %s", route.Mask)
			continue
		}
		mask := net.IPv4Mask(maskSlice[0], maskSlice[1], maskSlice[2], maskSlice[3])
		cidr, _ := mask.Size()

		routePrefix := netip.PrefixFrom(addr, cidr)
		if routePrefix.IsValid() && routePrefix.Addr().Is4() {
			prefixList = append(prefixList, routePrefix)
		}
	}
	return prefixList, nil
}

func addRouteToNonVPNIntf(prefix netip.Prefix, vpnIntf *iface.WGIface, intialNextHop net.IP, initialIntf *net.Interface) error {
	addr := prefix.Addr()
	switch {
	case addr.IsLoopback():
		return fmt.Errorf("adding route for loopback address %s is not allowed", prefix)
	case addr.IsLinkLocalUnicast():
		return fmt.Errorf("adding route for link-local unicast address %s is not allowed", prefix)
	case addr.IsLinkLocalMulticast():
		return fmt.Errorf("adding route for link-local multicast address %s is not allowed", prefix)
	case addr.IsInterfaceLocalMulticast():
		return fmt.Errorf("adding route for interface-local multicast address %s is not allowed", prefix)
	case addr.IsUnspecified():
		return fmt.Errorf("adding route for unspecified address %s is not allowed", prefix)
	case addr.IsMulticast():
		return fmt.Errorf("adding route for multicast address %s is not allowed", prefix)
	}

	// Determine the exit interface and next hop for the prefix, so we can add a specific route
	nexthop, intf, err := getNextHop(addr)
	if err != nil {
		return fmt.Errorf("get next hop: %s", err)
	}

	log.Debugf("Found next hop %s for prefix %s with interface %v", nexthop, prefix, intf)
	exitNextHop := nexthop
	var exitIntf string
	if intf != nil {
		exitIntf = intf.Name
	}

	// If the nexthop is our vpn gateway, we take the initial default gateway as nexthop
	if bytes.Compare(exitNextHop, vpnIntf.Address().IP) == 0 || exitIntf == vpnIntf.Name() {
		log.Debugf("Nexthop %s/%s is our vpn gateway, using initial next hop %s/%v", exitNextHop, exitIntf, intialNextHop, initialIntf)
		exitNextHop = intialNextHop
		if initialIntf != nil {
			exitIntf = initialIntf.Name
		} else {
			exitIntf = ""
		}
	}

	log.Debugf("Adding a new route for prefix %s with next hop %s", prefix, exitNextHop)
	return genericAddToRouteTable(prefix, exitNextHop.String(), exitIntf)
}

func addToRouteTableIfNoExists(prefix netip.Prefix, addr string, intf string) error {
	if prefix == defaultv4 {
		if err := genericAddToRouteTable(splitDefaultv4_1, addr, intf); err != nil {
			return err
		}
		if err := genericAddToRouteTable(splitDefaultv4_2, addr, intf); err != nil {
			if err2 := genericRemoveFromRouteTable(splitDefaultv4_1, addr, intf); err2 != nil {
				log.Warnf("Failed to rollback route addition: %s", err2)
			}
			return err
		}

		if err := addUnreachableRoute(splitDefaultv6_1); err != nil {
			return fmt.Errorf("add unreachable route split 1: %w", err)
		}
		if err := addUnreachableRoute(splitDefaultv6_2); err != nil {
			if err2 := genericRemoveFromRouteTable(splitDefaultv6_1, netip.IPv6Unspecified().String(), "1"); err2 != nil {
				log.Warnf("Failed to rollback route addition: %s", err2)
			}
			return fmt.Errorf("add unreachable route split 2: %w", err)
		}

		return nil
	}

	return genericAddToRouteTableIfNoExists(prefix, addr, intf)
}

func removeFromRouteTableIfNonSystem(prefix netip.Prefix, addr string, intf string) error {
	if prefix == defaultv4 {
		var result *multierror.Error
		if err := genericRemoveFromRouteTable(splitDefaultv4_1, addr, intf); err != nil {
			result = multierror.Append(result, err)
		}
		if err := genericRemoveFromRouteTable(splitDefaultv4_2, addr, intf); err != nil {
			result = multierror.Append(result, err)
		}
		if err := genericRemoveFromRouteTable(splitDefaultv6_1, netip.IPv6Unspecified().String(), "1"); err != nil {
			result = multierror.Append(result, err)
		}
		if err := genericRemoveFromRouteTable(splitDefaultv6_2, netip.IPv6Unspecified().String(), "1"); err != nil {
			result = multierror.Append(result, err)
		}
		return result.ErrorOrNil()
	}

	return genericRemoveFromRouteTableIfNonSystem(prefix, addr, intf)
}

func getPrefixFromIP(ip net.IP) (*netip.Prefix, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil, fmt.Errorf("parse IP address: %s", ip)
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}

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

func addUnreachableRoute(prefix netip.Prefix) error {
	args := []string{"route", "add", prefix.String(), netip.IPv6Unspecified().String(), "if", "1", "metric", "1"}

	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	log.Debugf("route add: %s", string(out))

	if err != nil {
		return fmt.Errorf("add route: %w", err)
	}
	return nil
}
