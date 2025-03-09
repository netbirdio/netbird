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
		return fmt.Errorf("failed to create route monitor: %w", err)
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
	intf := "<nil>"
	if route.Interface != nil {
		intf = route.Interface.Name
		if isSoftInterface(intf) {
			log.Debugf("Network monitor: ignoring default route change for soft interface %s", intf)
			return false
		}
	}

	switch route.Type {
	case systemops.RouteModified:
		// TODO: get routing table to figure out if our route is affected for modified routes
		log.Infof("Network monitor: default route changed: via %s, interface %s", route.NextHop, intf)
		return true
	case systemops.RouteAdded:
		if route.NextHop.Is4() && route.NextHop != nexthopv4.IP || route.NextHop.Is6() && route.NextHop != nexthopv6.IP {
			log.Infof("Network monitor: default route added: via %s, interface %s", route.NextHop, intf)
			return true
		}
	case systemops.RouteDeleted:
		if nexthopv4.Intf != nil && route.NextHop == nexthopv4.IP || nexthopv6.Intf != nil && route.NextHop == nexthopv6.IP {
			log.Infof("Network monitor: default route removed: via %s, interface %s", route.NextHop, intf)
			return true
		}
	}

	return false
}

func isSoftInterface(name string) bool {
	return strings.Contains(strings.ToLower(name), "isatap") || strings.Contains(strings.ToLower(name), "teredo")
}
