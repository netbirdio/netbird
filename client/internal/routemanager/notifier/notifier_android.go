//go:build android

package notifier

import (
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/route"
)

type Notifier struct {
	initialRoutes []*route.Route
	currentRoutes []*route.Route
	fakeIPRoute   *route.Route

	listener    listener.NetworkChangeListener
	listenerMux sync.Mutex
}

func NewNotifier() *Notifier {
	return &Notifier{}
}

func (n *Notifier) SetListener(listener listener.NetworkChangeListener) {
	n.listenerMux.Lock()
	defer n.listenerMux.Unlock()
	n.listener = listener
}

// SetInitialClientRoutes stores the initial route sets for TUN configuration.
func (n *Notifier) SetInitialClientRoutes(initialRoutes []*route.Route, routesForComparison []*route.Route) {
	n.initialRoutes = filterStatic(initialRoutes)
	n.currentRoutes = filterStatic(routesForComparison)
}

// SetFakeIPRoute stores the fake IP route to be included in every TUN rebuild.
func (n *Notifier) SetFakeIPRoute(r *route.Route) {
	n.fakeIPRoute = r
}

func (n *Notifier) OnNewRoutes(idMap route.HAMap) {
	var newRoutes []*route.Route
	for _, routes := range idMap {
		for _, r := range routes {
			if r.IsDynamic() {
				continue
			}
			newRoutes = append(newRoutes, r)
		}
	}

	if !n.hasRouteDiff(n.currentRoutes, newRoutes) {
		return
	}

	n.currentRoutes = newRoutes
	n.notify()
}

func (n *Notifier) OnNewPrefixes([]netip.Prefix) {
	// Not used on Android
}

func (n *Notifier) notify() {
	n.listenerMux.Lock()
	defer n.listenerMux.Unlock()
	if n.listener == nil {
		return
	}

	allRoutes := slices.Clone(n.currentRoutes)
	if n.fakeIPRoute != nil {
		allRoutes = append(allRoutes, n.fakeIPRoute)
	}

	routeStrings := n.routesToStrings(allRoutes)
	sort.Strings(routeStrings)
	go func(l listener.NetworkChangeListener) {
		l.OnNetworkChanged(strings.Join(n.addIPv6RangeIfNeeded(routeStrings, allRoutes), ","))
	}(n.listener)
}

func filterStatic(routes []*route.Route) []*route.Route {
	out := make([]*route.Route, 0, len(routes))
	for _, r := range routes {
		if !r.IsDynamic() {
			out = append(out, r)
		}
	}
	return out
}

func (n *Notifier) routesToStrings(routes []*route.Route) []string {
	nets := make([]string, 0, len(routes))
	for _, r := range routes {
		nets = append(nets, r.NetString())
	}
	return nets
}

func (n *Notifier) hasRouteDiff(a []*route.Route, b []*route.Route) bool {
	slices.SortFunc(a, func(x, y *route.Route) int {
		return strings.Compare(x.NetString(), y.NetString())
	})
	slices.SortFunc(b, func(x, y *route.Route) int {
		return strings.Compare(x.NetString(), y.NetString())
	})

	return !slices.EqualFunc(a, b, func(x, y *route.Route) bool {
		return x.NetString() == y.NetString()
	})
}

func (n *Notifier) GetInitialRouteRanges() []string {
	initialStrings := n.routesToStrings(n.initialRoutes)
	sort.Strings(initialStrings)
	return n.addIPv6RangeIfNeeded(initialStrings, n.initialRoutes)
}

func (n *Notifier) addIPv6RangeIfNeeded(inputRanges []string, routes []*route.Route) []string {
	for _, r := range routes {
		if r.Network.Addr().Is4() && r.Network.Bits() == 0 {
			return append(slices.Clone(inputRanges), "::/0")
		}
	}
	return inputRanges
}
