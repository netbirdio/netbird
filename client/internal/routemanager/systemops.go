package routemanager

import (
	"fmt"
	"github.com/libp2p/go-netroute"
	log "github.com/sirupsen/logrus"
	"net"
	"net/netip"
)

var errRouteNotFound = fmt.Errorf("route not found")

func addToRouteTableIfNoExists(prefix netip.Prefix, addr string) error {
	gateway, err := getExistingRIBRouteGateway(netip.MustParsePrefix("0.0.0.0/0"))
	if err != nil && err != errRouteNotFound {
		return err
	}
	prefixGateway, err := getExistingRIBRouteGateway(prefix)
	if err != nil && err != errRouteNotFound {
		return err
	}

	if prefixGateway != nil && !prefixGateway.Equal(gateway) {
		log.Warnf("route for network %s already exist and is pointing to the gateway: %s, won't add another one", prefix, prefixGateway)
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
	_, _, localGatewayAddress, err := r.Route(prefix.Addr().AsSlice())
	if err != nil {
		log.Errorf("getting routes returned an error: %v", err)
		return nil, errRouteNotFound
	}

	return localGatewayAddress, nil
}
