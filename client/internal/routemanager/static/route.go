package static

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/routemanager/common"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/route"
)

type Route struct {
	route                *route.Route
	routeRefCounter      *refcounter.RouteRefCounter
	allowedIPsRefcounter *refcounter.AllowedIPsRefCounter
	allowedIPsMu         sync.Mutex
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
	var merr *multierror.Error
	if err := r.RemoveAllowedIPs(); err != nil {
		merr = multierror.Append(merr, err)
	}
	if _, err := r.routeRefCounter.Decrement(r.route.Network); err != nil {
		merr = multierror.Append(merr, err)
	}
	return nberrors.FormatErrorOrNil(merr)
}

func (r *Route) AddAllowedIPs(peerKey string) error {
	r.allowedIPsMu.Lock()
	defer r.allowedIPsMu.Unlock()

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
	r.allowedIPsMu.Lock()
	defer r.allowedIPsMu.Unlock()

	var err error
	if _, decErr := r.allowedIPsRefcounter.Decrement(r.route.Network, r.currentPeerKey); decErr != nil {
		err = fmt.Errorf("remove allowed IP %s: %w", r.route.Network, decErr)
	}
	r.currentPeerKey = ""
	return err
}
