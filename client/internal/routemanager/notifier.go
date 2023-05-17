package routemanager

import (
	"sort"
	"sync"

	"github.com/netbirdio/netbird/route"
)

type OnNewRouteListener interface {
	OnNewRouteSetting()
}

type notifier struct {
	initialRouteIDs []string
	ids             []string

	routeListener    OnNewRouteListener
	routeListenerMux sync.Mutex
}

func newNotifier() *notifier {
	return &notifier{}
}

func (n *notifier) setListener(listener OnNewRouteListener) {
	n.routeListenerMux.Lock()
	defer n.routeListenerMux.Unlock()
	n.routeListener = listener
}

func (n *notifier) removeListener() {
	n.routeListenerMux.Lock()
	defer n.routeListenerMux.Unlock()
	n.routeListener = nil
}

func (n *notifier) setInitialClientRoutes(clientRoutes []*route.Route) {
	ids := make([]string, 0)
	for _, r := range clientRoutes {
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	n.initialRouteIDs = ids
}

func (n *notifier) onNewRoutes(idMap map[string][]*route.Route) {
	newIDs := make([]string, 0)
	for _, routes := range idMap {
		for _, r := range routes {
			newIDs = append(newIDs, r.ID)
		}
	}

	sort.Strings(newIDs)
	if !n.hasDiff(n.ids, newIDs) {
		return
	}

	n.ids = newIDs

	if !n.hasDiff(n.initialRouteIDs, newIDs) {
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

	go func(l OnNewRouteListener) {
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
