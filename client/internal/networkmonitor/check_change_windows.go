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

	// TODO: for the empty nexthop ip (on-link), determine the family differently
	nexthop := nexthopv4
	if route.NextHop.IP.Is6() {
		nexthop = nexthopv6
	}

	switch route.Type {
	case systemops.RouteModified, systemops.RouteAdded:
		// For added/modified routes, we care about different next hops
		if !nexthop.Equal(route.NextHop) {
			action := "changed"
			if route.Type == systemops.RouteAdded {
				action = "added"
			}
			log.Infof("Network monitor: default route %s: via %s", action, route.NextHop)
			return true
		}
	case systemops.RouteDeleted:
		// For deleted routes, we care about our tracked next hop being deleted
		if nexthop.Equal(route.NextHop) {
			log.Infof("Network monitor: default route removed: via %s", route.NextHop)
			return true
		}
	}

	return false
}

func isSoftInterface(name string) bool {
	return strings.Contains(strings.ToLower(name), "isatap") || strings.Contains(strings.ToLower(name), "teredo")
}
