package routemanager

import (
	"sort"
	"strings"
	"sync"

	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/route"
)

type notifier struct {
	initialRouteRangers []string
	routeRangers        []string

	listener    listener.NetworkChangeListener
	listenerMux sync.Mutex
}

func newNotifier() *notifier {
	return &notifier{}
}

func (n *notifier) setListener(listener listener.NetworkChangeListener) {
	n.listenerMux.Lock()
	defer n.listenerMux.Unlock()
	n.listener = listener
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
	if !n.hasDiff(n.initialRouteRangers, newNets) {
		return
	}

	n.routeRangers = newNets

	n.notify()
}

func (n *notifier) notify() {
	n.listenerMux.Lock()
	defer n.listenerMux.Unlock()
	if n.listener == nil {
		return
	}

	go func(l listener.NetworkChangeListener) {
		l.OnNetworkChanged(strings.Join(n.routeRangers, ","))
	}(n.listener)
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
