//go:build !android && !ios

package routemanager

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/libp2p/go-netroute"
	log "github.com/sirupsen/logrus"
)

var errRouteNotFound = fmt.Errorf("route not found")

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
