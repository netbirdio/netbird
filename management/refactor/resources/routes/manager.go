package routes

import (
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/refactor/resources/peers"
	"github.com/netbirdio/netbird/management/refactor/resources/peers/types"
	routeTypes "github.com/netbirdio/netbird/management/refactor/resources/routes/types"
	"github.com/netbirdio/netbird/route"
)

type Manager interface {
	GetRoutesToSync(peerID string, peersToConnect []*types.Peer, accountID string) []*routeTypes.Route
}

type DefaultManager struct {
	repository   Repository
	peersManager peers.Manager
}

func NewDefaultManager(repository Repository, peersManager peers.Manager) *DefaultManager {
	return &DefaultManager{
		repository:   repository,
		peersManager: peersManager,
	}
}

func (d DefaultManager) GetRoutesToSync(peerID string, peersToConnect []*types.Peer) []*routeTypes.Route {
	routes, peerDisabledRoutes := d.getRoutingPeerRoutes(peerID)
	peerRoutesMembership := make(lookupMap)
	for _, r := range append(routes, peerDisabledRoutes...) {
		peerRoutesMembership[route.GetHAUniqueID(r)] = struct{}{}
	}

	groupListMap := a.getPeerGroups(peerID)
	for _, peer := range aclPeers {
		activeRoutes, _ := a.getRoutingPeerRoutes(peer.ID)
		groupFilteredRoutes := a.filterRoutesByGroups(activeRoutes, groupListMap)
		filteredRoutes := a.filterRoutesFromPeersOfSameHAGroup(groupFilteredRoutes, peerRoutesMembership)
		routes = append(routes, filteredRoutes...)
	}

	return routes
}

func (d DefaultManager) getRoutingPeerRoutes(accountID, peerID string) (enabledRoutes []routeTypes.Route, disabledRoutes []routeTypes.Route) {
	peer, err := d.peersManager.GetPeerByID(peerID)
	if err != nil {
		log.Errorf("peer %s that doesn't exist under account %s", peerID, accountID)
		return nil, nil
	}

	// currently we support only linux routing peers
	if peer.Meta.GoOS != "linux" {
		return enabledRoutes, disabledRoutes
	}

	seenRoute := make(map[string]struct{})

	takeRoute := func(r routeTypes.Route, id string) {
		if _, ok := seenRoute[r.GetID()]; ok {
			return
		}
		seenRoute[r.GetID()] = struct{}{}

		if r.IsEnabled() {
			r.SetPeer(peer.GetKey())
			enabledRoutes = append(enabledRoutes, r)
			return
		}
		disabledRoutes = append(disabledRoutes, r)
	}

	for _, r := range a.Routes {
		for _, groupID := range r.PeerGroups {
			group := a.GetGroup(groupID)
			if group == nil {
				log.Errorf("route %s has peers group %s that doesn't exist under account %s", r.ID, groupID, a.Id)
				continue
			}
			for _, id := range group.Peers {
				if id != peerID {
					continue
				}

				newPeerRoute := r.Copy()
				newPeerRoute.Peer = id
				newPeerRoute.PeerGroups = nil
				newPeerRoute.ID = r.ID + ":" + id // we have to provide unique route id when distribute network map
				takeRoute(newPeerRoute, id)
				break
			}
		}
		if r.Peer == peerID {
			takeRoute(r.Copy(), peerID)
		}
	}

	return enabledRoutes, disabledRoutes
}
