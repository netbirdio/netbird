package server

import (
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"net/netip"
	"unicode/utf8"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/route"
)

// GetRoute gets a route object from account and route IDs
func (am *DefaultAccountManager) GetRoute(accountID string, routeID route.ID, userID string) (*route.Route, error) {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !(user.HasAdminPower() || user.IsServiceUser) {
		return nil, status.Errorf(status.PermissionDenied, "only users with admin power can view Network Routes")
	}

	wantedRoute, found := account.Routes[routeID]
	if found {
		return wantedRoute, nil
	}

	return nil, status.Errorf(status.NotFound, "route with ID %s not found", routeID)
}

// checkRoutePrefixExistsForPeers checks if a route with a given prefix exists for a single peer or multiple peer groups.
func (am *DefaultAccountManager) checkRoutePrefixExistsForPeers(account *Account, peerID string, routeID route.ID, peerGroupIDs []string, prefix netip.Prefix) error {
	// routes can have both peer and peer_groups
	routesWithPrefix := account.GetRoutesByPrefix(prefix)

	// lets remember all the peers and the peer groups from routesWithPrefix
	seenPeers := make(map[string]bool)
	seenPeerGroups := make(map[string]bool)

	for _, prefixRoute := range routesWithPrefix {
		// we skip route(s) with the same network ID as we want to allow updating of the existing route
		// when create a new route routeID is newly generated so nothing will be skipped
		if routeID == prefixRoute.ID {
			continue
		}

		if prefixRoute.Peer != "" {
			seenPeers[string(prefixRoute.ID)] = true
		}
		for _, groupID := range prefixRoute.PeerGroups {
			seenPeerGroups[groupID] = true

			group := account.GetGroup(groupID)
			if group == nil {
				return status.Errorf(
					status.InvalidArgument, "failed to add route with prefix %s - peer group %s doesn't exist",
					prefix.String(), groupID)
			}

			for _, pID := range group.Peers {
				seenPeers[pID] = true
			}
		}
	}

	if peerID != "" {
		// check that peerID exists and is not in any route as single peer or part of the group
		peer := account.GetPeer(peerID)
		if peer == nil {
			return status.Errorf(status.InvalidArgument, "peer with ID %s not found", peerID)
		}
		if _, ok := seenPeers[peerID]; ok {
			return status.Errorf(status.AlreadyExists,
				"failed to add route with prefix %s - peer %s already has this route", prefix.String(), peerID)
		}
	}

	// check that peerGroupIDs are not in any route peerGroups list
	for _, groupID := range peerGroupIDs {
		group := account.GetGroup(groupID) // we validated the group existent before entering this function, o need to check again.

		if _, ok := seenPeerGroups[groupID]; ok {
			return status.Errorf(
				status.AlreadyExists, "failed to add route with prefix %s - peer group %s already has this route",
				prefix.String(), group.Name)
		}

		// check that the peers from peerGroupIDs groups are not the same peers we saw in routesWithPrefix
		for _, id := range group.Peers {
			if _, ok := seenPeers[id]; ok {
				peer := account.GetPeer(id)
				if peer == nil {
					return status.Errorf(status.InvalidArgument, "peer with ID %s not found", peerID)
				}
				return status.Errorf(status.AlreadyExists,
					"failed to add route with prefix %s - peer %s from the group %s already has this route",
					prefix.String(), peer.Name, group.Name)
			}
		}
	}

	return nil
}

// CreateRoute creates and saves a new route
func (am *DefaultAccountManager) CreateRoute(accountID, network, peerID string, peerGroupIDs []string, description string, netID route.NetID, masquerade bool, metric int, groups []string, enabled bool, userID string) (*route.Route, error) {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	if peerID != "" && len(peerGroupIDs) != 0 {
		return nil, status.Errorf(
			status.InvalidArgument,
			"peer with ID %s and peers group %s should not be provided at the same time",
			peerID, peerGroupIDs)
	}

	var newRoute route.Route
	newRoute.ID = route.ID(xid.New().String())

	prefixType, newPrefix, err := route.ParseNetwork(network)
	if err != nil {
		return nil, status.Errorf(status.InvalidArgument, "failed to parse IP %s", network)
	}

	if len(peerGroupIDs) > 0 {
		err = validateGroups(peerGroupIDs, account.Groups)
		if err != nil {
			return nil, err
		}
	}

	err = am.checkRoutePrefixExistsForPeers(account, peerID, newRoute.ID, peerGroupIDs, newPrefix)
	if err != nil {
		return nil, err
	}

	if metric < route.MinMetric || metric > route.MaxMetric {
		return nil, status.Errorf(status.InvalidArgument, "metric should be between %d and %d", route.MinMetric, route.MaxMetric)
	}

	if utf8.RuneCountInString(string(netID)) > route.MaxNetIDChar || netID == "" {
		return nil, status.Errorf(status.InvalidArgument, "identifier should be between 1 and %d", route.MaxNetIDChar)
	}

	err = validateGroups(groups, account.Groups)
	if err != nil {
		return nil, err
	}

	newRoute.Peer = peerID
	newRoute.PeerGroups = peerGroupIDs
	newRoute.Network = newPrefix
	newRoute.NetworkType = prefixType
	newRoute.Description = description
	newRoute.NetID = netID
	newRoute.Masquerade = masquerade
	newRoute.Metric = metric
	newRoute.Enabled = enabled
	newRoute.Groups = groups

	if account.Routes == nil {
		account.Routes = make(map[route.ID]*route.Route)
	}

	account.Routes[newRoute.ID] = &newRoute

	// IPv6 route must only be created with IPv6 enabled peers, creating an IPv6 enabled route may enable IPv6 for
	// peers with V6Setting = Auto.
	if peerID != "" && prefixType == route.IPv6Network && newRoute.Enabled {
		peer := account.GetPeer(peerID)
		if peer.V6Setting == nbpeer.V6Disabled || !peer.Meta.Ipv6Supported {
			return nil, status.Errorf(
				status.InvalidArgument,
				"IPv6 must be enabled for peer %s to be used in route %s",
				peer.Name, newPrefix.String())
		} else if peer.IP6 == nil {
			_, err = am.DeterminePeerV6(account, peer)
			if err != nil {
				return nil, err
			}
			account.UpdatePeer(peer)
		}

	}

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return nil, err
	}

	am.updateAccountPeers(account)

	am.StoreEvent(userID, string(newRoute.ID), accountID, activity.RouteCreated, newRoute.EventMeta())

	return &newRoute, nil
}

// SaveRoute saves route
func (am *DefaultAccountManager) SaveRoute(accountID, userID string, routeToSave *route.Route) error {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	if routeToSave == nil {
		return status.Errorf(status.InvalidArgument, "route provided is nil")
	}

	if !routeToSave.Network.IsValid() {
		return status.Errorf(status.InvalidArgument, "invalid Prefix %s", routeToSave.Network.String())
	}

	if routeToSave.Metric < route.MinMetric || routeToSave.Metric > route.MaxMetric {
		return status.Errorf(status.InvalidArgument, "metric should be between %d and %d", route.MinMetric, route.MaxMetric)
	}

	if utf8.RuneCountInString(string(routeToSave.NetID)) > route.MaxNetIDChar || routeToSave.NetID == "" {
		return status.Errorf(status.InvalidArgument, "identifier should be between 1 and %d", route.MaxNetIDChar)
	}

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	if routeToSave.Peer != "" && len(routeToSave.PeerGroups) != 0 {
		return status.Errorf(status.InvalidArgument, "peer with ID and peer groups should not be provided at the same time")
	}

	if routeToSave.Peer != "" {
		peer := account.GetPeer(routeToSave.Peer)
		if peer == nil {
			return status.Errorf(status.InvalidArgument, "provided peer does not exist")
		}
		if routeToSave.NetworkType == route.IPv6Network && routeToSave.Enabled && (!peer.Meta.Ipv6Supported || peer.V6Setting == nbpeer.V6Disabled) {
			return status.Errorf(status.InvalidArgument, "peer with IPv6 disabled can't be used for IPv6 route")
		}
	}

	if len(routeToSave.PeerGroups) > 0 {
		err = validateGroups(routeToSave.PeerGroups, account.Groups)
		if err != nil {
			return err
		}
	}

	err = am.checkRoutePrefixExistsForPeers(account, routeToSave.Peer, routeToSave.ID, routeToSave.Copy().PeerGroups, routeToSave.Network)
	if err != nil {
		return err
	}

	err = validateGroups(routeToSave.Groups, account.Groups)
	if err != nil {
		return err
	}

	oldRoute := account.Routes[routeToSave.ID]

	account.Routes[routeToSave.ID] = routeToSave

	// Check if old peer's IPv6 status needs to be recalculated.
	// Must happen if route is an IPv6 route, and either:
	// - The routing peer has changed
	// - The route has been disabled
	// - (the route has been enabled) => caught in the next if-block
	if oldRoute.Peer != "" && routeToSave.NetworkType == route.IPv6Network && ((oldRoute.Enabled && !routeToSave.Enabled) || oldRoute.Peer != routeToSave.Peer) {
		oldPeer := account.GetPeer(oldRoute.Peer)
		if oldPeer.V6Setting == nbpeer.V6Auto {
			changed, err := am.DeterminePeerV6(account, oldPeer)
			if err != nil {
				return err
			}
			if changed {
				account.UpdatePeer(oldPeer)
			}
		}
	}
	// Check if new peer's IPv6 status needs to be recalculated.
	// Must happen if route is an IPv6 route, and either:
	// - The routing peer has changed
	// - The route has been enabled
	// - (The route has been disabled) => caught in previous if-block
	if oldRoute.Peer != "" && routeToSave.NetworkType == route.IPv6Network && routeToSave.Enabled && (!oldRoute.Enabled || oldRoute.Peer != routeToSave.Peer) {
		newPeer := account.GetPeer(routeToSave.Peer)
		if newPeer.V6Setting == nbpeer.V6Disabled || !newPeer.Meta.Ipv6Supported {
			return status.Errorf(
				status.InvalidArgument,
				"IPv6 must be enabled for peer %s to be used in route %s",
				newPeer.Name, routeToSave.Network.String())
		} else if newPeer.IP6 == nil {
			_, err = am.DeterminePeerV6(account, newPeer)
			if err != nil {
				return err
			}
			account.UpdatePeer(newPeer)
		}

	}

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	am.updateAccountPeers(account)

	am.StoreEvent(userID, string(routeToSave.ID), accountID, activity.RouteUpdated, routeToSave.EventMeta())

	return nil
}

// DeleteRoute deletes route with routeID
func (am *DefaultAccountManager) DeleteRoute(accountID string, routeID route.ID, userID string) error {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	routy := account.Routes[routeID]
	if routy == nil {
		return status.Errorf(status.NotFound, "route with ID %s doesn't exist", routeID)
	}
	delete(account.Routes, routeID)

	// If the route was an IPv6 route, deleting it may update the automatic IPv6 enablement status of its routing peers,
	// check if this is the case and update accordingly.
	if routy.Peer != "" && routy.Enabled && routy.NetworkType == route.IPv6Network {
		oldPeer := account.GetPeer(routy.Peer)
		if oldPeer.V6Setting == nbpeer.V6Auto {
			changed, err := am.DeterminePeerV6(account, oldPeer)
			if err != nil {
				return err
			}
			if changed {
				account.UpdatePeer(oldPeer)
			}
		}
	}

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	am.StoreEvent(userID, string(routy.ID), accountID, activity.RouteRemoved, routy.EventMeta())

	am.updateAccountPeers(account)

	return nil
}

// ListRoutes returns a list of routes from account
func (am *DefaultAccountManager) ListRoutes(accountID, userID string) ([]*route.Route, error) {
	unlock := am.Store.AcquireAccountWriteLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !(user.HasAdminPower() || user.IsServiceUser) {
		return nil, status.Errorf(status.PermissionDenied, "only users with admin power can view Network Routes")
	}

	routes := make([]*route.Route, 0, len(account.Routes))
	for _, item := range account.Routes {
		routes = append(routes, item)
	}

	return routes, nil
}

func toProtocolRoute(route *route.Route) *proto.Route {
	return &proto.Route{
		ID:          string(route.ID),
		NetID:       string(route.NetID),
		Network:     route.Network.String(),
		NetworkType: int64(route.NetworkType),
		Peer:        route.Peer,
		Metric:      int64(route.Metric),
		Masquerade:  route.Masquerade,
	}
}

func toProtocolRoutes(routes []*route.Route) []*proto.Route {
	protoRoutes := make([]*proto.Route, 0)
	for _, r := range routes {
		protoRoutes = append(protoRoutes, toProtocolRoute(r))
	}
	return protoRoutes
}
