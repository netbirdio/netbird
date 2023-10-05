package routemanager

import (
	"sort"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/route"
)

// RouteListener is a callback interface for mobile system
type RouteListener interface {
	// OnNewRouteSetting invoke when new route setting has been arrived
	OnNewRouteSetting(string, string)
}

type notifier struct {
	// ownIPAddr is the ip address of the netbird interface including the netmask
	ownIPAddr           string
	initialRouteRangers []string
	routeRangers        []string

	routeListener    RouteListener
	routeListenerMux sync.Mutex
}

func newNotifier(ip string) *notifier {
	log.Debugf("creating notifier with own ip: %s", ip)
	return &notifier{
		ownIPAddr: ip,
	}
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
		log.Debugf("notifying route listener with route ranges: %s and own ip: %s", strings.Join(n.routeRangers, ","), n.ownIPAddr)
		l.OnNewRouteSetting(strings.Join(n.routeRangers, ","), n.ownIPAddr)
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
