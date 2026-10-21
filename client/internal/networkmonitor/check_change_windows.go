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

	ifaceEvents, states, stop := watchInterfaces()
	if stop != nil {
		defer stop()
	}
	if states == nil {
		// The interfaces moved while subscribing: report it now.
		return nil
	}

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
		case <-ifaceEvents:
			current, err := readInterfaceStates()
			if err != nil {
				log.Debugf("Network monitor: %v", err)
				continue
			}
			if index, changed := states.changed(current); changed {
				log.Infof("Network monitor: interface %d went %s", index, upOrDown(current[index]))
				return nil
			}
			states = current
		}
	}
}

// watchInterfaces subscribes to interface changes and returns the states to
// compare them with. The states are read before and after subscribing, so a
// change in between is not lost: it comes back as nil states. Without
// interface events the channel is nil and only route events count.
func watchInterfaces() (<-chan struct{}, interfaceStates, func()) {
	before, err := readInterfaceStates()
	if err != nil {
		log.Warnf("Network monitor: interface changes not watched: %v", err)
		return nil, interfaceStates{}, nil
	}
	events, stop, err := subscribeInterfaceChanges()
	if err != nil {
		log.Warnf("Network monitor: interface changes not watched: %v", err)
		return nil, before, nil
	}
	after, err := readInterfaceStates()
	if err != nil {
		log.Debugf("Network monitor: %v", err)
		return events, before, stop
	}
	if _, changed := before.changed(after); changed {
		return events, nil, stop
	}
	return events, after, stop
}

func upOrDown(up bool) string {
	if up {
		return "up"
	}
	return "down"
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
		return handleRouteAddedOrModified(route, nexthop)
	case systemops.RouteDeleted:
		return handleRouteDeleted(route, nexthop)
	}

	return false
}

func handleRouteAddedOrModified(route systemops.RouteUpdate, nexthop systemops.Nexthop) bool {
	// For added/modified routes, we care about different next hops
	if !nexthop.Equal(route.NextHop) {
		action := "changed"
		if route.Type == systemops.RouteAdded {
			action = "added"
		}
		log.Infof("Network monitor: default route %s: via %s", action, route.NextHop)
		return true
	}
	return false
}

func handleRouteDeleted(route systemops.RouteUpdate, nexthop systemops.Nexthop) bool {
	// For deleted routes, we care about our tracked next hop being deleted
	if nexthop.Equal(route.NextHop) {
		log.Infof("Network monitor: default route removed: via %s", route.NextHop)
		return true
	}
	return false
}

func isSoftInterface(name string) bool {
	return strings.Contains(strings.ToLower(name), "isatap") || strings.Contains(strings.ToLower(name), "teredo")
}
