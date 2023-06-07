package routemanager

import (
	"sort"
	"sync"

	"github.com/netbirdio/netbird/route"
)

// RouteListener is a callback interface for mobile system
type RouteListener interface {
	// OnNewRouteSetting invoke when new route setting has been arrived
	OnNewRouteSetting()
}

type notifier struct {
	initialRouteRangers []string
	routeRangers        []string

	routeListener    RouteListener
	routeListenerMux sync.Mutex
}

func newNotifier() *notifier {
	return &notifier{}
}

func (n *notifier) setListener(listener RouteListener) {
	n.routeListenerMux.Lock()
	defer n.routeListenerMux.Unlock()
	n.routeListener = listener
}

func (n *notifier) setInitialClientRoutes(clientRoutes []*route.Route) {
	nets := make([]string, 0)
	for _, r := range clientRoutes {
		nets = append(nets, r.Network.String())
	}
	sort.Strings(nets)
	n.initialRouteRangers = nets
}

func (n *notifier) onNewRoutes(idMap map[string][]*route.Route) {
	newNets := make([]string, 0)
	for _, routes := range idMap {
		for _, r := range routes {
			newNets = append(newNets, r.Network.String())
		}
	}

	sort.Strings(newNets)
	if !n.hasDiff(n.routeRangers, newNets) {
		return
	}

	n.routeRangers = newNets

	if !n.hasDiff(n.initialRouteRangers, newNets) {
		return
	}
	n.notify()
}

func (n *notifier) notify() {
	n.routeListenerMux.Lock()
	defer n.routeListenerMux.Unlock()
	if n.routeListener == nil {
		return
	}

	go func(l RouteListener) {
		l.OnNewRouteSetting()
	}(n.routeListener)
}

func (n *notifier) hasDiff(a []string, b []string) bool {
	if len(a) != len(b) {
		return true
	}
	for i, v := range a {
		if v != b[i] {
			return true
		}
	}
	return false
}

func (n *notifier) initialRouteRanges() []string {
	return n.initialRouteRangers
}
