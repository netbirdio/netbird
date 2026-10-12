//go:build android

package notifier

import (
	"net/netip"
	"sync"

	"github.com/netbirdio/netbird/client/internal/listener"
	"github.com/netbirdio/netbird/route"
)

type Notifier struct {
	mu sync.Mutex

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

func (n *Notifier) Close() {
	// unused
}
