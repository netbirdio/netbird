package static

import (
	"context"

	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/iface"
	"github.com/netbirdio/netbird/route"
)

type Route struct {
	route           *route.Route
	wgInterface     *iface.WGIface
	routeRefCounter *refcounter.Counter
}

func NewRoute(rt *route.Route, wgIface *iface.WGIface, routeRefCounter *refcounter.Counter) *Route {
	return &Route{
		route:           rt,
		wgInterface:     wgIface,
		routeRefCounter: routeRefCounter,
	}
}

// Route route methods
func (r *Route) String() string {
	return r.route.Network.String()
}

func (r *Route) AddRoute(context.Context) error {
	return r.routeRefCounter.Increment(r.route.Network)
}

func (r *Route) RemoveRoute() error {
	return r.routeRefCounter.Decrement(r.route.Network)
}

func (r *Route) AddAllowedIPs(peerKey string) error {
	return r.wgInterface.AddAllowedIP(peerKey, r.route.Network.String())
}

func (r *Route) RemoveAllowedIPs(peerKey string) error {
	return r.wgInterface.RemoveAllowedIP(peerKey, r.route.Network.String())
}
