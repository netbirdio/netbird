package notifier

import (
	"net/netip"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/route"
)

type Notifier struct {
	initialRoutes       []*route.Route
	routesForComparison []*route.Route
	dnsFeatureFlag      bool

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

func (n *Notifier) SetInitialClientRoutes(allRoutes []*route.Route, routesForComparison []*route.Route, dnsFeatureFlag bool) {
	n.dnsFeatureFlag = dnsFeatureFlag
	n.initialRoutes = allRoutes
	n.routesForComparison = routesForComparison
}

func (n *Notifier) OnNewRoutes(idMap route.HAMap) {
	if runtime.GOOS != "android" {
		return
	}

	var newRoutes []*route.Route
	for _, routes := range idMap {
		newRoutes = append(newRoutes, routes...)
	}

	if !n.hasRouteDiff(n.routesForComparison, newRoutes) {
		return
	}

	n.routesForComparison = newRoutes
	n.notify()
}

// OnNewPrefixes is called from iOS only
func (n *Notifier) OnNewPrefixes(prefixes []netip.Prefix) {
	newNets := make([]string, 0)
	for _, prefix := range prefixes {
		newNets = append(newNets, prefix.String())
	}

	sort.Strings(newNets)

	currentNets := n.routesToStrings(n.routesForComparison)
	if slices.Equal(currentNets, newNets) {
		return
	}

	n.notify()
}

func (n *Notifier) notify() {
	n.listenerMux.Lock()
	defer n.listenerMux.Unlock()
	if n.listener == nil {
		return
	}

	routeStrings := n.routesToStrings(n.routesForComparison)
	sort.Strings(routeStrings)
	go func(l listener.NetworkChangeListener) {
		l.OnNetworkChanged(strings.Join(n.addIPv6RangeIfNeeded(routeStrings, n.routesForComparison), ","))
	}(n.listener)
}

// hasRouteDiff compares two route slices for differences
func (n *Notifier) hasRouteDiff(a []*route.Route, b []*route.Route) bool {
	aFiltered := n.filterRoutes(a)
	bFiltered := n.filterRoutes(b)

	slices.SortFunc(aFiltered, func(x, y *route.Route) int {
		return strings.Compare(x.NetString(), y.NetString())
	})
	slices.SortFunc(bFiltered, func(x, y *route.Route) int {
		return strings.Compare(x.NetString(), y.NetString())
	})

	return !slices.EqualFunc(aFiltered, bFiltered, func(x, y *route.Route) bool {
		return x.NetString() == y.NetString()
	})
}

// filterRoutes filters routes based on DNS feature flag
func (n *Notifier) filterRoutes(routes []*route.Route) []*route.Route {
	filtered := make([]*route.Route, 0, len(routes))
	for _, r := range routes {
		if r.IsDynamic() && !n.dnsFeatureFlag {
			// this kind of dynamic route is not supported on android
			continue
		}
		filtered = append(filtered, r)
	}
	return filtered
}

// routesToStrings converts routes to string slice (caller should sort if needed)
func (n *Notifier) routesToStrings(routes []*route.Route) []string {
	filtered := n.filterRoutes(routes)
	nets := make([]string, 0, len(filtered))
	for _, r := range filtered {
		nets = append(nets, r.NetString())
	}
	return nets
}

func (n *Notifier) GetInitialRouteRanges() []string {
	initialStrings := n.routesToStrings(n.initialRoutes)
	sort.Strings(initialStrings)
	return n.addIPv6RangeIfNeeded(initialStrings, n.initialRoutes)
}

// addIPv6RangeIfNeeded returns the input ranges with the default IPv6 range when there is an IPv4 default route.
func (n *Notifier) addIPv6RangeIfNeeded(inputRanges []string, routes []*route.Route) []string {
	for _, r := range routes {
		// we are intentionally adding the ipv6 default range in case of ipv4 default range
		// to ensure that all traffic is managed by the tunnel interface on android
		if r.Network.Addr().Is4() && r.Network.Bits() == 0 {
			return append(slices.Clone(inputRanges), "::/0")
		}
	}
	return inputRanges
}
