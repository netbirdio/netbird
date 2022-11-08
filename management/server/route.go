package server

import (
	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/route"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net/netip"
	"strconv"
	"unicode/utf8"
)

const (
	// UpdateRouteDescription indicates a route description update operation
	UpdateRouteDescription RouteUpdateOperationType = iota
	// UpdateRouteNetwork indicates a route IP update operation
	UpdateRouteNetwork
	// UpdateRoutePeer indicates a route peer update operation
	UpdateRoutePeer
	// UpdateRouteMetric indicates a route metric update operation
	UpdateRouteMetric
	// UpdateRouteMasquerade indicates a route masquerade update operation
	UpdateRouteMasquerade
	// UpdateRouteEnabled indicates a route enabled update operation
	UpdateRouteEnabled
	// UpdateRouteNetworkIdentifier indicates a route net ID update operation
	UpdateRouteNetworkIdentifier
)

// RouteUpdateOperationType operation type
type RouteUpdateOperationType int

func (t RouteUpdateOperationType) String() string {
	switch t {
	case UpdateRouteDescription:
		return "UpdateRouteDescription"
	case UpdateRouteNetwork:
		return "UpdateRouteNetwork"
	case UpdateRoutePeer:
		return "UpdateRoutePeer"
	case UpdateRouteMetric:
		return "UpdateRouteMetric"
	case UpdateRouteMasquerade:
		return "UpdateRouteMasquerade"
	case UpdateRouteEnabled:
		return "UpdateRouteEnabled"
	case UpdateRouteNetworkIdentifier:
		return "UpdateRouteNetworkIdentifier"
	default:
		return "InvalidOperation"
	}
}

// RouteUpdateOperation operation object with type and values to be applied
type RouteUpdateOperation struct {
	Type   RouteUpdateOperationType
	Values []string
}

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
		return nil, Errorf(PermissionDenied, "Only administrators can view Network Routes")
	}

	wantedRoute, found := account.Routes[routeID]
	if found {
		return wantedRoute, nil
	}

	return nil, status.Errorf(codes.NotFound, "route with ID %s not found", routeID)
}

// checkPrefixPeerExists checks the combination of prefix and peer id, if it exists returns an error, otherwise returns nil
func (am *DefaultAccountManager) checkPrefixPeerExists(accountID, peer string, prefix netip.Prefix) error {

	if peer == "" {
		return nil
	}

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	routesWithPrefix := account.GetRoutesByPrefix(prefix)

	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			return nil
		}
		return status.Errorf(codes.InvalidArgument, "failed to parse prefix %s", prefix.String())
	}
	for _, prefixRoute := range routesWithPrefix {
		if prefixRoute.Peer == peer {
			return status.Errorf(codes.AlreadyExists, "failed a route with prefix %s and peer already exist", prefix.String())
		}
	}
	return nil
}

// CreateRoute creates and saves a new route
func (am *DefaultAccountManager) CreateRoute(accountID string, network, peer, description, netID string, masquerade bool, metric int, enabled bool) (*route.Route, error) {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	var newRoute route.Route
	prefixType, newPrefix, err := route.ParseNetwork(network)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse IP %s", network)
	}
	err = am.checkPrefixPeerExists(accountID, peer, newPrefix)
	if err != nil {
		return nil, err
	}

	if peer != "" {
		_, peerExist := account.Peers[peer]
		if !peerExist {
			return nil, status.Errorf(codes.InvalidArgument, "failed to find Peer %s", peer)
		}
	}

	if metric < route.MinMetric || metric > route.MaxMetric {
		return nil, status.Errorf(codes.InvalidArgument, "metric should be between %d and %d", route.MinMetric, route.MaxMetric)
	}

	if utf8.RuneCountInString(netID) > route.MaxNetIDChar || netID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "identifier should be between 1 and %d", route.MaxNetIDChar)
	}

	newRoute.Peer = peer
	newRoute.ID = xid.New().String()
	newRoute.Network = newPrefix
	newRoute.NetworkType = prefixType
	newRoute.Description = description
	newRoute.NetID = netID
	newRoute.Masquerade = masquerade
	newRoute.Metric = metric
	newRoute.Enabled = enabled

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
		return &newRoute, status.Errorf(codes.Unavailable, "failed to update peers after create route %s", newPrefix)
	}
	return &newRoute, nil
}

// SaveRoute saves route
func (am *DefaultAccountManager) SaveRoute(accountID string, routeToSave *route.Route) error {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	if routeToSave == nil {
		return status.Errorf(codes.InvalidArgument, "route provided is nil")
	}

	if !routeToSave.Network.IsValid() {
		return status.Errorf(codes.InvalidArgument, "invalid Prefix %s", routeToSave.Network.String())
	}

	if routeToSave.Metric < route.MinMetric || routeToSave.Metric > route.MaxMetric {
		return status.Errorf(codes.InvalidArgument, "metric should be between %d and %d", route.MinMetric, route.MaxMetric)
	}

	if utf8.RuneCountInString(routeToSave.NetID) > route.MaxNetIDChar || routeToSave.NetID == "" {
		return status.Errorf(codes.InvalidArgument, "identifier should be between 1 and %d", route.MaxNetIDChar)
	}

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	if routeToSave.Peer != "" {
		_, peerExist := account.Peers[routeToSave.Peer]
		if !peerExist {
			return status.Errorf(codes.InvalidArgument, "failed to find Peer %s", routeToSave.Peer)
		}
	}

	account.Routes[routeToSave.ID] = routeToSave

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	return am.updateAccountPeers(account)
}

// UpdateRoute updates existing route with set of operations
func (am *DefaultAccountManager) UpdateRoute(accountID, routeID string, operations []RouteUpdateOperation) (*route.Route, error) {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, err
	}

	routeToUpdate, ok := account.Routes[routeID]
	if !ok {
		return nil, Errorf(RouteNotFound, "route %s no longer exists", routeID)
	}

	newRoute := routeToUpdate.Copy()

	for _, operation := range operations {

		if len(operation.Values) != 1 {
			return nil, status.Errorf(codes.InvalidArgument, "operation %s contains invalid number of values, it should be 1", operation.Type.String())
		}

		switch operation.Type {
		case UpdateRouteDescription:
			newRoute.Description = operation.Values[0]
		case UpdateRouteNetworkIdentifier:
			if utf8.RuneCountInString(operation.Values[0]) > route.MaxNetIDChar || operation.Values[0] == "" {
				return nil, status.Errorf(codes.InvalidArgument, "identifier should be between 1 and %d", route.MaxNetIDChar)
			}
			newRoute.NetID = operation.Values[0]
		case UpdateRouteNetwork:
			prefixType, prefix, err := route.ParseNetwork(operation.Values[0])
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "failed to parse IP %s", operation.Values[0])
			}
			err = am.checkPrefixPeerExists(accountID, routeToUpdate.Peer, prefix)
			if err != nil {
				return nil, err
			}
			newRoute.Network = prefix
			newRoute.NetworkType = prefixType
		case UpdateRoutePeer:
			if operation.Values[0] != "" {
				_, peerExist := account.Peers[operation.Values[0]]
				if !peerExist {
					return nil, status.Errorf(codes.InvalidArgument, "failed to find Peer %s", operation.Values[0])
				}
			}

			err = am.checkPrefixPeerExists(accountID, operation.Values[0], routeToUpdate.Network)
			if err != nil {
				return nil, err
			}
			newRoute.Peer = operation.Values[0]
		case UpdateRouteMetric:
			metric, err := strconv.Atoi(operation.Values[0])
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "failed to parse metric %s, not int", operation.Values[0])
			}
			if metric < route.MinMetric || metric > route.MaxMetric {
				return nil, status.Errorf(codes.InvalidArgument, "failed to parse metric %s, value should be %d > N < %d",
					operation.Values[0],
					route.MinMetric,
					route.MaxMetric,
				)
			}
			newRoute.Metric = metric
		case UpdateRouteMasquerade:
			masquerade, err := strconv.ParseBool(operation.Values[0])
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "failed to parse masquerade %s, not boolean", operation.Values[0])
			}
			newRoute.Masquerade = masquerade
		case UpdateRouteEnabled:
			enabled, err := strconv.ParseBool(operation.Values[0])
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "failed to parse enabled %s, not boolean", operation.Values[0])
			}
			newRoute.Enabled = enabled
		}
	}

	account.Routes[routeID] = newRoute

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return nil, err
	}

	err = am.updateAccountPeers(account)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update account peers")
	}
	return newRoute, nil
}

// DeleteRoute deletes route with routeID
func (am *DefaultAccountManager) DeleteRoute(accountID, routeID string) error {
	unlock := am.Store.AcquireAccountLock(accountID)
	defer unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return err
	}

	delete(account.Routes, routeID)

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

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
		return nil, Errorf(PermissionDenied, "Only administrators can view Network Routes")
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
