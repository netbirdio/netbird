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

func genericAddRouteForCurrentDefaultGateway(prefix netip.Prefix) error {
	defaultGateway, err := getExistingRIBRouteGateway(defaultv4)
	if err != nil && !errors.Is(err, errRouteNotFound) {
		return fmt.Errorf("get existing route gateway: %s", err)
	}

	addr := netip.MustParseAddr(defaultGateway.String())

	if !prefix.Contains(addr) {
		log.Debugf("Skipping adding a new route for gateway %s because it is not in the network %s", addr, prefix)
		return nil
	}

	gatewayPrefix := netip.PrefixFrom(addr, 32)

	ok, err := existsInRouteTable(gatewayPrefix)
	if err != nil {
		return fmt.Errorf("unable to check if there is an existing route for gateway %s. error: %s", gatewayPrefix, err)
	}

	if ok {
		log.Debugf("Skipping adding a new route for gateway %s because it already exists", gatewayPrefix)
		return nil
	}

	gatewayHop, err := getExistingRIBRouteGateway(gatewayPrefix)
	if err != nil && !errors.Is(err, errRouteNotFound) {
		return fmt.Errorf("unable to get the next hop for the default gateway address. error: %s", err)
	}
	log.Debugf("Adding a new route for gateway %s with next hop %s", gatewayPrefix, gatewayHop)
	return genericAddToRouteTable(gatewayPrefix, gatewayHop.String(), "")
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

func genericAddToRouteTable(prefix netip.Prefix, addr, _ string) error {
	cmd := exec.Command("route", "add", prefix.String(), addr)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("add route: %w", err)
	}
	log.Debugf(string(out))
	return nil
}

func genericRemoveFromRouteTable(prefix netip.Prefix, addr, _ string) error {
	args := []string{"delete", prefix.String()}
	if runtime.GOOS == "darwin" {
		args = append(args, addr)
	}
	cmd := exec.Command("route", args...)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("remove route: %w", err)
	}
	log.Debugf(string(out))
	return nil
}

func getExistingRIBRouteGateway(prefix netip.Prefix) (net.IP, error) {
	r, err := netroute.New()
	if err != nil {
		return nil, fmt.Errorf("new netroute: %w", err)
	}
	_, gateway, preferredSrc, err := r.Route(prefix.Addr().AsSlice())
	if err != nil {
		log.Errorf("Getting routes returned an error: %v", err)
		return nil, errRouteNotFound
	}

	if gateway == nil {
		return preferredSrc, nil
	}

	return gateway, nil
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
