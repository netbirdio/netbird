//go:build !android

//nolint:unused
package routemanager

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"

	"github.com/libp2p/go-netroute"
	log "github.com/sirupsen/logrus"
)

var errRouteNotFound = fmt.Errorf("route not found")

// TODO: fix: for default our wg address now appears as the default gw
func genericAddRouteForCurrentDefaultGateway(prefix netip.Prefix) error {
	defaultGateway, err := getExistingRIBRouteGateway(defaultv4)
	if err != nil && !errors.Is(err, errRouteNotFound) {
		return fmt.Errorf("get existing route gateway: %s", err)
	}

	addr, ok := netip.AddrFromSlice(defaultGateway)
	if !ok {
		return fmt.Errorf("parse IP address: %s", defaultGateway)
	}

	if !prefix.Contains(addr) {
		log.Debugf("Skipping adding a new route for gateway %s because it is not in the network %s", addr, prefix)
		return nil
	}

	gatewayPrefix := netip.PrefixFrom(addr, 32)

	ok, err = existsInRouteTable(gatewayPrefix)
	if err != nil {
		return fmt.Errorf("unable to check if there is an existing route for gateway %s. error: %s", gatewayPrefix, err)
	}

	if ok {
		log.Debugf("Skipping adding a new route for gateway %s because it already exists", gatewayPrefix)
		return nil
	}

	var exitIntf string
	gatewayHop, intf, err := getNextHop(gatewayPrefix.Addr())
	if err != nil && !errors.Is(err, errRouteNotFound) {
		return fmt.Errorf("unable to get the next hop for the default gateway address. error: %s", err)
	}
	if intf != nil {
		exitIntf = intf.Name
	}

	log.Debugf("Adding a new route for gateway %s with next hop %s", gatewayPrefix, gatewayHop)
	return genericAddToRouteTable(gatewayPrefix, gatewayHop.String(), exitIntf)
}

func genericAddToRouteTableIfNoExists(prefix netip.Prefix, addr string, intf string) error {
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
		err := genericAddRouteForCurrentDefaultGateway(prefix)
		if err != nil {
			log.Warnf("Unable to add route for current default gateway route. Will proceed without it. error: %s", err)
		}
	}

	return genericAddToRouteTable(prefix, addr, intf)
}

func genericRemoveFromRouteTableIfNonSystem(prefix netip.Prefix, addr string, intf string) error {
	return genericRemoveFromRouteTable(prefix, addr, intf)
}

func genericAddToRouteTable(prefix netip.Prefix, nexthop, intf string) error {
	if intf != "" && runtime.GOOS == "windows" {
		script := fmt.Sprintf(
			`New-NetRoute -DestinationPrefix "%s" -InterfaceAlias "%s" -NextHop "%s" -Confirm:$False`,
			prefix,
			intf,
			nexthop,
		)
		_, err := exec.Command("powershell", "-Command", script).CombinedOutput()
		if err != nil {
			return fmt.Errorf("PowerShell add route: %w", err)
		}
	} else {
		args := []string{"route", "add", prefix.String(), nexthop}
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		log.Debugf("route add output: %s", string(out))
		if err != nil {
			return fmt.Errorf("route add: %w", err)
		}
	}
	return nil
}

func genericRemoveFromRouteTable(prefix netip.Prefix, nexthop, intf string) error {
	args := []string{"route", "delete", prefix.String()}
	if runtime.GOOS != "windows" {
		args = append(args, nexthop)
	}

	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	log.Debugf("route delete: %s", string(out))

	if err != nil {
		return fmt.Errorf("remove route: %w", err)
	}
	return nil
}

func getExistingRIBRouteGateway(prefix netip.Prefix) (net.IP, error) {
	gateway, _, err := getNextHop(prefix.Addr())
	return gateway, err
}

func getNextHop(ip netip.Addr) (net.IP, *net.Interface, error) {
	r, err := netroute.New()
	if err != nil {
		return nil, nil, fmt.Errorf("new netroute: %w", err)
	}
	intf, gateway, preferredSrc, err := r.Route(ip.AsSlice())
	if err != nil {
		log.Errorf("Getting routes returned an error: %v", err)
		return nil, nil, errRouteNotFound
	}

	log.Debugf("Route for %s: interface %v, nexthop %v, preferred source %v", ip, intf, gateway, preferredSrc)
	if gateway == nil {
		log.Debugf("No next hop found for ip %s, using preferred source %s", ip, preferredSrc)
		return preferredSrc, intf, nil
	}

	return gateway, intf, nil
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
		if isPrefixSupported(tableRoute) && tableRoute.Contains(prefix.Addr()) && tableRoute.Bits() < prefix.Bits() {
			return true, nil
		}
	}
	return false, nil
}
