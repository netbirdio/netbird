package routemanager

import (
	"fmt"
	"github.com/libp2p/go-netroute"
	log "github.com/sirupsen/logrus"
	"net"
	"net/netip"
)

var RouteNotFound = fmt.Errorf("route not found")

func addToRouteTableIfNoExists(prefix netip.Prefix, addr string) error {
	gatewayIface, err := getExistingRIBRoute(netip.MustParsePrefix("0.0.0.0/0"))
	if err != nil {
		return err
	}
	iface, err := getExistingRIBRoute(prefix)
	if err != nil && err != RouteNotFound {
		return err
	}
	if iface != nil && iface.Name != gatewayIface.Name {

		log.Warnf("route for network %s already exist and is pointing to interface %s, won't add another one", prefix, iface.Name)
		return nil
	}
	return addToRouteTable(prefix, addr)
}

func removeFromRouteTableIfNonSystem(prefix netip.Prefix, wireguardIfaceName string) error {
	iface, err := getExistingRIBRoute(prefix)
	if err != nil {
		return err
	}
	if iface != nil && iface.Name != wireguardIfaceName {
		log.Warnf("route for network %s is pointing to a different interface %s, should be pointing to %s, not removing", prefix, iface.Name, wireguardIfaceName)
		return nil
	}
	return removeFromRouteTable(prefix)
}

func getExistingRIBRoute(prefix netip.Prefix) (*net.Interface, error) {
	r, err := netroute.New()
	if err != nil {
		return nil, err
	}
	iface, _, _, err := r.Route(prefix.Addr().AsSlice())
	if err != nil {
		log.Errorf("getting routes returned an error: %v", err)
		return nil, RouteNotFound
	}
	return iface, nil
}
