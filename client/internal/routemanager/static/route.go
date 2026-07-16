package static

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/routemanager/common"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/route"
)

type Route struct {
	route                *route.Route
	routeRefCounter      *refcounter.RouteRefCounter
	allowedIPsRefcounter *refcounter.AllowedIPsRefCounter
	// currentPeerKey is the routing peer this watcher currently has the prefix installed on
	// (the HA winner elected by the watcher). It can differ from route.Peer and change on
	// failover, so it is recorded on AddAllowedIPs and used on RemoveAllowedIPs to decrement
	// the exact peer that was incremented.
	currentPeerKey string
}

func NewRoute(params common.HandlerParams) *Route {
	return &Route{
		route:                params.Route,
		routeRefCounter:      params.RouteRefCounter,
		allowedIPsRefcounter: params.AllowedIPsRefCounter,
	}
}

func (r *Route) String() string {
	return r.route.Network.String()
}

func (r *Route) AddRoute(context.Context) error {
	if _, err := r.routeRefCounter.Increment(r.route.Network, struct{}{}); err != nil {
		return err
	}
	return nil
}

func (r *Route) RemoveRoute() error {
	if _, err := r.routeRefCounter.Decrement(r.route.Network); err != nil {
		return err
	}
	return nil
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
	r.currentPeerKey = peerKey
	return nil
}

func (r *Route) RemoveAllowedIPs() error {
	if _, err := r.allowedIPsRefcounter.Decrement(r.route.Network, r.currentPeerKey); err != nil {
		return err
	}
	r.currentPeerKey = ""
	return nil
}
