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
)

const (
	// UpdateRouteDescription indicates a route description update operation
	UpdateRouteDescription RouteUpdateOperationType = iota
	// UpdateRoutePrefix indicates a route IP update operation
	UpdateRoutePrefix
	// UpdateRoutePeer indicates a route peer update operation
	UpdateRoutePeer
	// UpdateRouteMetric indicates a route metric update operation
	UpdateRouteMetric
	// UpdateRouteMasquerade indicates a route masquerade update operation
	UpdateRouteMasquerade
	// UpdateRouteEnabled indicates a route enabled update operation
	UpdateRouteEnabled
)

// RouteUpdateOperationType operation type
type RouteUpdateOperationType int

func (t RouteUpdateOperationType) String() string {
	switch t {
	case UpdateRouteDescription:
		return "UpdateRouteDescription"
	case UpdateRoutePrefix:
		return "UpdateRoutePrefix"
	case UpdateRoutePeer:
		return "UpdateRoutePeer"
	case UpdateRouteMetric:
		return "UpdateRouteMetric"
	case UpdateRouteMasquerade:
		return "UpdateRouteMasquerade"
	case UpdateRouteEnabled:
		return "UpdateRouteEnabled"
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
func (am *DefaultAccountManager) GetRoute(accountID, routeID string) (*route.Route, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	rule, ok := account.Routes[routeID]
	if ok {
		return rule, nil
	}

	return nil, status.Errorf(codes.NotFound, "route with ID %s not found", routeID)
}

// checkPrefixPeerExists checks the combination of prefix and peer id, if it exists returns an error, otehrwise returns nil
func (am *DefaultAccountManager) checkPrefixPeerExists(accountID, peer string, prefix netip.Prefix) error {
	routesWithPrefix, err := am.Store.GetRoutesByPrefix(accountID, prefix)

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
func (am *DefaultAccountManager) CreateRoute(accountID string, prefix, peer, description string, masquerade bool, metric int, enabled bool) (*route.Route, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	var newRoute route.Route
	prefixType, newPrefix, err := route.ParsePrefix(prefix)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "failed to parse IP %s", prefix)
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

	newRoute.Peer = peer
	newRoute.ID = xid.New().String()
	newRoute.Prefix = newPrefix
	newRoute.PrefixType = prefixType
	newRoute.Description = description
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
	am.mux.Lock()
	defer am.mux.Unlock()

	if routeToSave == nil {
		return status.Errorf(codes.InvalidArgument, "route provided is nil")
	}

	if !routeToSave.Prefix.IsValid() {
		return status.Errorf(codes.InvalidArgument, "invalid Prefix %s", routeToSave.Prefix.String())
	}

	if routeToSave.Metric < route.MinMetric || routeToSave.Metric > route.MaxMetric {
		return status.Errorf(codes.InvalidArgument, "metric should be between %d and %d", route.MinMetric, route.MaxMetric)
	}

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return status.Errorf(codes.NotFound, "account not found")
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
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	routeToUpdate, ok := account.Routes[routeID]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "rule %s no longer exists", routeID)
	}

	newRoute := routeToUpdate.Copy()

	for _, operation := range operations {

		if len(operation.Values) != 1 {
			return nil, status.Errorf(codes.InvalidArgument, "operation %s contains invalid number of values, it should be 1", operation.Type.String())
		}

		switch operation.Type {
		case UpdateRouteDescription:
			newRoute.Description = operation.Values[0]
		case UpdateRoutePrefix:
			prefixType, prefix, err := route.ParsePrefix(operation.Values[0])
			if err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "failed to parse IP %s", operation.Values[0])
			}
			err = am.checkPrefixPeerExists(accountID, routeToUpdate.Peer, prefix)
			if err != nil {
				return nil, err
			}
			newRoute.Prefix = prefix
			newRoute.PrefixType = prefixType
		case UpdateRoutePeer:
			if operation.Values[0] != "" {
				_, peerExist := account.Peers[operation.Values[0]]
				if !peerExist {
					return nil, status.Errorf(codes.InvalidArgument, "failed to find Peer %s", operation.Values[0])
				}
			}

			err = am.checkPrefixPeerExists(accountID, operation.Values[0], routeToUpdate.Prefix)
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
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return status.Errorf(codes.NotFound, "account not found")
	}

	delete(account.Routes, routeID)

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(account); err != nil {
		return err
	}

	return am.updateAccountPeers(account)
}

// ListRoutes returns a list of routes from account
func (am *DefaultAccountManager) ListRoutes(accountID string) ([]*route.Route, error) {
	am.mux.Lock()
	defer am.mux.Unlock()

	account, err := am.Store.GetAccount(accountID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	routes := make([]*route.Route, 0, len(account.Routes))
	for _, item := range account.Routes {
		routes = append(routes, item)
	}

	return routes, nil
}

func toProtocolRoute(route *route.Route) *proto.Route {
	return &proto.Route{
		ID:         route.ID,
		Prefix:     route.Prefix.String(),
		PrefixType: int64(route.PrefixType),
		Peer:       route.Peer,
		Metric:     int64(route.Metric),
		Masquerade: route.Masquerade,
	}
}

func (am *DefaultAccountManager) getPeersRoutes(peers []*Peer) []*route.Route {
	routes := make([]*route.Route, 0)
	for _, peer := range peers {
		peerRoutes, err := am.Store.GetPeerRoutes(peer.Key)
		if err != nil {
			errorStatus, ok := status.FromError(err)
			if !ok && errorStatus.Code() != codes.NotFound {
				log.Error(err)
			}
			continue
		}
		activeRoutes := make([]*route.Route, 0)
		for _, pr := range peerRoutes {
			if pr.Enabled {
				activeRoutes = append(activeRoutes, pr)
			}
		}
		if len(activeRoutes) > 0 {
			routes = append(routes, activeRoutes...)
		}
	}
	return routes
}

func toProtocolRoutes(routes []*route.Route) []*proto.Route {
	protoRoutes := make([]*proto.Route, 0)
	for _, r := range routes {
		protoRoutes = append(protoRoutes, toProtocolRoute(r))
	}
	return protoRoutes
}
