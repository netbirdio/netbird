package server

import (
	"net/netip"
	"unicode/utf8"

	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/route"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
)

// GetRoute gets a route object from account and route IDs
func (am *DefaultAccountManager) GetRoute(accountID, routeID, userID string) (*route.Route, error) {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !user.IsAdmin() {
		return nil, status.Errorf(status.PermissionDenied, "Only administrators can view Network Routes")
	}

	wantedRoute, found := account.Routes[routeID]
	if found {
		return wantedRoute, nil
	}

	return nil, status.Errorf(status.NotFound, "route with ID %s not found", routeID)
}

// checkPrefixPeerExists checks the combination of prefix and peer id, if it exists returns an error, otherwise returns nil
func (am *DefaultAccountManager) checkPrefixPeerExists(accountID, peerID string, prefix netip.Prefix) error {

	if peerID == "" {
		return nil
	}

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	routesWithPrefix := account.GetRoutesByPrefix(prefix)

	for _, prefixRoute := range routesWithPrefix {
		if prefixRoute.Peer == peerID {
			return status.Errorf(status.AlreadyExists, "failed to add route with prefix %s - peer already has this route", prefix.String())
		}
	}
	return nil
}

// CreateRoute creates and saves a new route
func (am *DefaultAccountManager) CreateRoute(accountID string, network, peerID, description, netID string, masquerade bool, metric int, groups []string, enabled bool, userID string) (*route.Route, error) {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	if peerID != "" {
		peer := account.GetPeer(peerID)
		if peer == nil {
			return nil, status.Errorf(status.InvalidArgument, "peer with ID %s not found", peerID)
		}
	}

	var newRoute route.Route
	prefixType, newPrefix, err := route.ParseNetwork(network)
	if err != nil {
		return nil, status.Errorf(status.InvalidArgument, "failed to parse IP %s", network)
	}
	err = am.checkPrefixPeerExists(accountID, peerID, newPrefix)
	if err != nil {
		return nil, err
	}

	if metric < route.MinMetric || metric > route.MaxMetric {
		return nil, status.Errorf(status.InvalidArgument, "metric should be between %d and %d", route.MinMetric, route.MaxMetric)
	}

	if utf8.RuneCountInString(netID) > route.MaxNetIDChar || netID == "" {
		return nil, status.Errorf(status.InvalidArgument, "identifier should be between 1 and %d", route.MaxNetIDChar)
	}

	err = validateGroups(groups, account.Groups)
	if err != nil {
		return nil, err
	}

	newRoute.Peer = peerID
	newRoute.ID = xid.New().String()
	newRoute.Network = newPrefix
	newRoute.NetworkType = prefixType
	newRoute.Description = description
	newRoute.NetID = netID
	newRoute.Masquerade = masquerade
	newRoute.Metric = metric
	newRoute.Enabled = enabled
	newRoute.Groups = groups

	if account.Routes == nil {
		account.Routes = make(map[string]*route.Route)
	}

	account.Routes[newRoute.ID] = &newRoute

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return nil, err
	}

	err = am.updateAccountPeers(account)
	if err != nil {
		log.Error(err)
		return &newRoute, status.Errorf(status.Internal, "failed to update peers after create route %s", newPrefix)
	}

	am.storeEvent(userID, newRoute.ID, accountID, activity.RouteCreated, newRoute.EventMeta())

	return &newRoute, nil
}

// SaveRoute saves route
func (am *DefaultAccountManager) SaveRoute(accountID, userID string, routeToSave *route.Route) error {
	unlock := am.Store.AcquireAccountLock(accountID)
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

	if utf8.RuneCountInString(routeToSave.NetID) > route.MaxNetIDChar || routeToSave.NetID == "" {
		return status.Errorf(status.InvalidArgument, "identifier should be between 1 and %d", route.MaxNetIDChar)
	}

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	if routeToSave.Peer != "" {
		peer := account.GetPeer(routeToSave.Peer)
		if peer == nil {
			return status.Errorf(status.InvalidArgument, "peer with ID %s not found", routeToSave.Peer)
		}
	}

	err = validateGroups(routeToSave.Groups, account.Groups)
	if err != nil {
		return err
	}

	account.Routes[routeToSave.ID] = routeToSave

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	err = am.updateAccountPeers(account)
	if err != nil {
		return err
	}

	am.storeEvent(userID, routeToSave.ID, accountID, activity.RouteUpdated, routeToSave.EventMeta())

	return nil
}

// DeleteRoute deletes route with routeID
func (am *DefaultAccountManager) DeleteRoute(accountID, routeID, userID string) error {
	unlock := am.Store.AcquireAccountLock(accountID)
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

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	am.storeEvent(userID, routy.ID, accountID, activity.RouteRemoved, routy.EventMeta())

	return am.updateAccountPeers(account)
}

// ListRoutes returns a list of routes from account
func (am *DefaultAccountManager) ListRoutes(accountID, userID string) ([]*route.Route, error) {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	user, err := account.FindUser(userID)
	if err != nil {
		return nil, err
	}

	if !user.IsAdmin() {
		return nil, status.Errorf(status.PermissionDenied, "Only administrators can view Network Routes")
	}

	routes := make([]*route.Route, 0, len(account.Routes))
	for _, item := range account.Routes {
		routes = append(routes, item)
	}

	return routes, nil
}

func toProtocolRoute(route *route.Route) *proto.Route {
	return &proto.Route{
		ID:          route.ID,
		NetID:       route.NetID,
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
