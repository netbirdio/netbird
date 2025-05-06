package networkmonitor

import (
	"context"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

func checkChange(ctx context.Context, nexthopv4, nexthopv6 systemops.Nexthop) error {
	routeMonitor, err := systemops.NewRouteMonitor(ctx)
	if err != nil {
		return fmt.Errorf("create route monitor: %w", err)
	}
	defer func() {
		if err := routeMonitor.Stop(); err != nil {
			log.Errorf("Network monitor: failed to stop route monitor: %v", err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case route := <-routeMonitor.RouteUpdates():
			if route.Destination.Bits() != 0 {
				continue
			}

			if routeChanged(route, nexthopv4, nexthopv6) {
				return nil
			}
		}
	}
}

func routeChanged(route systemops.RouteUpdate, nexthopv4, nexthopv6 systemops.Nexthop) bool {
	if intf := route.NextHop.Intf; intf != nil && isSoftInterface(intf.Name) {
		log.Debugf("Network monitor: ignoring default route change for next hop with soft interface %s", route.NextHop)
		return false
	}

	switch route.Type {
	case systemops.RouteModified:
		// TODO: get routing table to figure out if our route is affected for modified routes

		// Ignore changes to our tracked routes where neither next hop ip nor interface have changed.
		if route.NextHop.IP.Is4() && !nexthopv4.Equal(route.NextHop) || route.NextHop.IP.Is6() && !nexthopv6.Equal(route.NextHop) {
			log.Infof("Network monitor: default route changed: via %s", route.NextHop)
			return true
		}
	case systemops.RouteAdded:
		// We are only interested in new routes that are different
		if route.NextHop.IP.Is4() && !nexthopv4.Equal(route.NextHop) || route.NextHop.IP.Is6() && !nexthopv6.Equal(route.NextHop) {
			log.Infof("Network monitor: default route added: via %s", route.NextHop)
			return true
		}
	case systemops.RouteDeleted:
		// We are only interested in our tracked routes being deleted
		if route.NextHop.IP.Is4() && nexthopv4.Equal(route.NextHop) || route.NextHop.IP.Is6() && nexthopv6.Equal(route.NextHop) {
			log.Infof("Network monitor: default route removed: via %s", route.NextHop)
			return true
		}
	}

	return false
}

func isSoftInterface(name string) bool {
	return strings.Contains(strings.ToLower(name), "isatap") || strings.Contains(strings.ToLower(name), "teredo")
}
