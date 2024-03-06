//go:build !android && !ios

package routemanager

import (
	"errors"
	"fmt"
	"net"
	"net/netip"

	"github.com/libp2p/go-netroute"
	log "github.com/sirupsen/logrus"
)

var errRouteNotFound = fmt.Errorf("route not found")

func addToRouteTableIfNoExists(prefix netip.Prefix, addr string, intf string) error {
	ok, err := existsInRouteTable(prefix)
	if err != nil {
		return err
	}
	if ok {
		log.Warnf("skipping adding a new route for network %s because it already exists", prefix)
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

	return addToRouteTable(prefix, addr, intf)
}

func addRouteForCurrentDefaultGateway(prefix netip.Prefix) error {
	defaultGateway, err := getExistingRIBRouteGateway(defaultv4)
	if err != nil && !errors.Is(err, errRouteNotFound) {
		return err
	}

	addr := netip.MustParseAddr(defaultGateway.String())

	if !prefix.Contains(addr) {
		log.Debugf("skipping adding a new route for gateway %s because it is not in the network %s", addr, prefix)
		return nil
	}

	gatewayPrefix := netip.PrefixFrom(addr, 32)

	ok, err := existsInRouteTable(gatewayPrefix)
	if err != nil {
		return fmt.Errorf("unable to check if there is an existing route for gateway %s. error: %s", gatewayPrefix, err)
	}

	if ok {
		log.Debugf("skipping adding a new route for gateway %s because it already exists", gatewayPrefix)
		return nil
	}

	gatewayHop, err := getExistingRIBRouteGateway(gatewayPrefix)
	if err != nil && !errors.Is(err, errRouteNotFound) {
		return fmt.Errorf("unable to get the next hop for the default gateway address. error: %s", err)
	}
	log.Debugf("adding a new route for gateway %s with next hop %s", gatewayPrefix, gatewayHop)
	return addToRouteTable(gatewayPrefix, gatewayHop.String(), "")
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

func removeFromRouteTableIfNonSystem(prefix netip.Prefix, addr string, intf string) error {
	return removeFromRouteTable(prefix, addr, intf)
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
