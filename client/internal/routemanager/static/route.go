package static

import (
	"context"

	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/route"
)

type Route struct {
	route                *route.Route
	routeRefCounter      *refcounter.RouteRefCounter
	allowedIPsRefcounter *refcounter.AllowedIPsRefCounter
}

func NewRoute(rt *route.Route, routeRefCounter *refcounter.RouteRefCounter, allowedIPsRefCounter *refcounter.AllowedIPsRefCounter) *Route {
	return &Route{
		route:                rt,
		routeRefCounter:      routeRefCounter,
		allowedIPsRefcounter: allowedIPsRefCounter,
	}
}

// Route route methods
func (r *Route) String() string {
	return r.route.Network.String()
}

func (r *Route) AddRoute(context.Context) error {
	_, err := r.routeRefCounter.Increment(r.route.Network, nil)
	return err
}

func (r *Route) RemoveRoute() error {
	_, err := r.routeRefCounter.Decrement(r.route.Network)
	return err
}

func (r *Route) AddAllowedIPs(peerKey string) error {
	_, err := r.allowedIPsRefcounter.Increment(r.route.Network, peerKey)
	return err
}

func (r *Route) RemoveAllowedIPs() error {
	_, err := r.allowedIPsRefcounter.Decrement(r.route.Network)
	return err
}
