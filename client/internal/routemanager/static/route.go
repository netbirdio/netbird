package static

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

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
	_, err := r.routeRefCounter.Increment(r.route.Network, struct{}{})
	return err
}

func (r *Route) RemoveRoute() error {
	_, err := r.routeRefCounter.Decrement(r.route.Network)
	return err
}

func (r *Route) AddAllowedIPs(peerKey string) error {
	if ref, err := r.allowedIPsRefcounter.Increment(r.route.Network, peerKey); err != nil {
		return fmt.Errorf("add allowed IP %s: %w", r.route.Network, err)
	} else if ref.Count > 1 && ref.Out != peerKey {
		log.Warnf("Prefix [%s] is already routed by peer [%s]. HA routing disabled",
			r.route.Network,
			ref.Out,
		)
	}
	return nil
}

func (r *Route) RemoveAllowedIPs() error {
	_, err := r.allowedIPsRefcounter.Decrement(r.route.Network)
	return err
}
