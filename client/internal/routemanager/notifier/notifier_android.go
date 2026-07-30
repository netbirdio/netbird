//go:build android

package notifier

import (
	"net/netip"
	"slices"
	"sort"
	"sync"

	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/route"
)

type Notifier struct {
	mu sync.Mutex

	initialRoutes []*route.Route
	// currentRoutes is the last announced route set. It exists only to
	// suppress noise: without it every network map sync would trigger the
	// Java side, even when the routes did not change. The actual TUN route
	// state is owned by the route manager and pulled from there.
	currentRoutes []*route.Route

	listener listener.NetworkChangeListener
}

func NewNotifier() *Notifier {
	return &Notifier{}
}

func (n *Notifier) SetListener(listener listener.NetworkChangeListener) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.listener = listener
}

// SetInitialClientRoutes stores the initial route sets for TUN configuration.
func (n *Notifier) SetInitialClientRoutes(initialRoutes []*route.Route, routesForComparison []*route.Route) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.initialRoutes = filterStatic(initialRoutes)
	n.currentRoutes = filterStatic(routesForComparison)
}

func (n *Notifier) NotifyRouteChange() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.notifyLocked()
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

	n.mu.Lock()
	defer n.mu.Unlock()
	if !hasRouteDiff(n.currentRoutes, newRoutes) {
		return
	}

	n.currentRoutes = newRoutes
	n.notifyLocked()
}

func (n *Notifier) OnNewPrefixes([]netip.Prefix) {
	// Not used on Android
}

func (n *Notifier) notifyLocked() {
	if n.listener == nil {
		return
	}
	n.listener.OnNetworkChanged("")
}

func (n *Notifier) GetInitialRouteRanges() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	initialStrings := routesToStrings(n.initialRoutes)
	sort.Strings(initialStrings)
	return initialStrings
}

func (n *Notifier) Close() {
	// unused
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

func routesToStrings(routes []*route.Route) []string {
	nets := make([]string, 0, len(routes))
	for _, r := range routes {
		nets = append(nets, r.NetString())
	}
	return nets
}

func hasRouteDiff(a []*route.Route, b []*route.Route) bool {
	as := routesToStrings(a)
	bs := routesToStrings(b)
	sort.Strings(as)
	sort.Strings(bs)
	return !slices.Equal(as, bs)
}
