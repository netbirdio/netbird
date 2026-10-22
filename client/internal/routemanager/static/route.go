package static

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/hashicorp/go-multierror"
	log "github.com/sirupsen/logrus"

	nberrors "github.com/netbirdio/netbird/client/errors"
	"github.com/netbirdio/netbird/client/internal/routemanager/common"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
	"github.com/netbirdio/netbird/route"
)

type Route struct {
	route                *route.Route
	prefixes             []netip.Prefix
	routeRefCounter      *refcounter.RouteRefCounter
	allowedIPsRefcounter *refcounter.AllowedIPsRefCounter
	// currentPeerKey is the routing peer this watcher currently has the prefixes installed on
	// (the HA winner elected by the watcher). It can differ from route.Peer and change on
	// failover, so it is recorded on AddAllowedIPs and used on RemoveAllowedIPs to decrement
	// the exact peer that was incremented.
	currentPeerKey string
}

func NewRoute(params common.HandlerParams) *Route {
	return newRoute(params, []netip.Prefix{params.Route.Network})
}

func newRoute(params common.HandlerParams, prefixes []netip.Prefix) *Route {
	return &Route{
		route:                params.Route,
		prefixes:             prefixes,
		routeRefCounter:      params.RouteRefCounter,
		allowedIPsRefcounter: params.AllowedIPsRefCounter,
	}
}

func (r *Route) String() string {
	return r.route.NetString()
}

func (r *Route) AddRoute(context.Context) error {
	for i, prefix := range r.prefixes {
		if _, err := r.routeRefCounter.Increment(prefix, struct{}{}); err != nil {
			if rollbackErr := r.removeRoutes(r.prefixes[:i]); rollbackErr != nil {
				log.Warnf("failed to roll back routes of [%s]: %v", r, rollbackErr)
			}
			return err
		}
	}
	return nil
}

func (r *Route) RemoveRoute() error {
	return r.removeRoutes(r.prefixes)
}

func (r *Route) removeRoutes(prefixes []netip.Prefix) error {
	var merr *multierror.Error
	for _, prefix := range prefixes {
		if _, err := r.routeRefCounter.Decrement(prefix); err != nil {
			merr = multierror.Append(merr, err)
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}

func (r *Route) AddAllowedIPs(peerKey string) error {
	for i, prefix := range r.prefixes {
		ref, err := r.allowedIPsRefcounter.Increment(prefix, peerKey)
		if err != nil {
			if rollbackErr := r.removeAllowedIPs(r.prefixes[:i], peerKey); rollbackErr != nil {
				log.Warnf("failed to roll back allowed IPs of [%s]: %v", r, rollbackErr)
			}
			return fmt.Errorf("add allowed IP %s: %w", prefix, err)
		}
		if ref.Count > 1 && ref.Out != peerKey {
			log.Warnf("Prefix [%s] is already routed by peer [%s]. HA routing disabled",
				prefix,
				ref.Out,
			)
		}
	}
	r.currentPeerKey = peerKey
	return nil
}

func (r *Route) RemoveAllowedIPs() error {
	err := r.removeAllowedIPs(r.prefixes, r.currentPeerKey)
	r.currentPeerKey = ""
	return err
}

func (r *Route) removeAllowedIPs(prefixes []netip.Prefix, peerKey string) error {
	var merr *multierror.Error
	for _, prefix := range prefixes {
		if _, err := r.allowedIPsRefcounter.Decrement(prefix, peerKey); err != nil {
			merr = multierror.Append(merr, fmt.Errorf("remove allowed IP %s: %w", prefix, err))
		}
	}
	return nberrors.FormatErrorOrNil(merr)
}
