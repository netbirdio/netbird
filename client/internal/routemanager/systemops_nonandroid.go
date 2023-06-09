//go:build !android

package routemanager

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/libp2p/go-netroute"
	log "github.com/sirupsen/logrus"
)

var errRouteNotFound = fmt.Errorf("route not found")

func addToRouteTableIfNoExists(prefix netip.Prefix, addr string) error {
	defaultGateway, err := getExistingRIBRouteGateway(netip.MustParsePrefix("0.0.0.0/0"))
	if err != nil && err != errRouteNotFound {
		return err
	}

	gatewayIP := netip.MustParseAddr(defaultGateway.String())
	if prefix.Contains(gatewayIP) {
		log.Warnf("skipping adding a new route for network %s because it overlaps with the default gateway: %s", prefix, gatewayIP)
		return nil
	}

	ok, err := existsInRouteTable(prefix)
	if err != nil {
		return err
	}
	if ok {
		log.Warnf("skipping adding a new route for network %s because it already exists", prefix)
		return nil
	}

	return addToRouteTable(prefix, addr)
}

func removeFromRouteTableIfNonSystem(prefix netip.Prefix, addr string) error {
	addrIP := net.ParseIP(addr)
	prefixGateway, err := getExistingRIBRouteGateway(prefix)
	if err != nil {
		return err
	}
	if prefixGateway != nil && !prefixGateway.Equal(addrIP) {
		log.Warnf("route for network %s is pointing to a different gateway: %s, should be pointing to: %s, not removing", prefix, prefixGateway, addrIP)
		return nil
	}
	return removeFromRouteTable(prefix)
}

func getExistingRIBRouteGateway(prefix netip.Prefix) (net.IP, error) {
	r, err := netroute.New()
	if err != nil {
		return nil, err
	}
	_, gateway, _, err := r.Route(prefix.Addr().AsSlice())
	if err != nil {
		log.Errorf("getting routes returned an error: %v", err)
		return nil, errRouteNotFound
	}

	return gateway, nil
}
