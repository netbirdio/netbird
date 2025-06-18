package server

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"unicode/utf8"

	"github.com/rs/xid"

	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/permissions/modules"
	"github.com/netbirdio/netbird/management/server/permissions/operations"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

// GetRoute gets a route object from account and route IDs
func (am *DefaultAccountManager) GetRoute(ctx context.Context, accountID string, routeID route.ID, userID string) (*route.Route, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Routes, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return am.Store.GetRouteByID(ctx, store.LockingStrengthShare, accountID, string(routeID))
}

// checkRoutePrefixOrDomainsExistForPeers checks if a route with a given prefix exists for a single peer or multiple peer groups.
func checkRoutePrefixOrDomainsExistForPeers(ctx context.Context, transaction store.Store, accountID string, checkRoute *route.Route, groupsMap map[string]*types.Group) error {
	// routes can have both peer and peer_groups
	prefix := checkRoute.Network
	domains := checkRoute.Domains

	routesWithPrefix, err := getRoutesByPrefixOrDomains(ctx, transaction, accountID, prefix, domains)
	if err != nil {
		return err
	}

	// lets remember all the peers and the peer groups from routesWithPrefix
	seenPeers := make(map[string]bool)
	seenPeerGroups := make(map[string]bool)

	for _, prefixRoute := range routesWithPrefix {
		// we skip route(s) with the same network ID as we want to allow updating of the existing route
		// when creating a new route routeID is newly generated so nothing will be skipped
		if checkRoute.ID == prefixRoute.ID {
			continue
		}

		if prefixRoute.Peer != "" {
			seenPeers[string(prefixRoute.ID)] = true
		}

		peerGroupsMap, err := transaction.GetGroupsByIDs(ctx, store.LockingStrengthShare, accountID, prefixRoute.PeerGroups)
		if err != nil {
			return err
		}

		for _, groupID := range prefixRoute.PeerGroups {
			seenPeerGroups[groupID] = true

			group, ok := peerGroupsMap[groupID]
			if !ok || group == nil {
				return status.Errorf(
					status.InvalidArgument, "failed to add route with %s - peer group %s doesn't exist",
					getRouteDescriptor(prefix, domains), groupID,
				)
			}

			for _, pID := range group.Peers {
				seenPeers[pID] = true
			}
		}
	}

	if peerID := checkRoute.Peer; peerID != "" {
		// check that peerID exists and is not in any route as single peer or part of the group
		_, err = transaction.GetPeerByID(context.Background(), store.LockingStrengthShare, accountID, peerID)
		if err != nil {
			return status.Errorf(status.InvalidArgument, "peer with ID %s not found", peerID)
		}

		if _, ok := seenPeers[peerID]; ok {
			return status.Errorf(status.AlreadyExists,
				"failed to add route with %s - peer %s already has this route", getRouteDescriptor(prefix, domains), peerID)
		}
	}

	// check that peerGroupIDs are not in any route peerGroups list
	for _, groupID := range checkRoute.PeerGroups {
		group := groupsMap[groupID] // we validated the group existence before entering this function, no need to check again.
		if _, ok := seenPeerGroups[groupID]; ok {
			return status.Errorf(
				status.AlreadyExists, "failed to add route with %s - peer group %s already has this route",
				getRouteDescriptor(prefix, domains), group.Name)
		}

		// check that the peers from peerGroupIDs groups are not the same peers we saw in routesWithPrefix
		peersMap, err := transaction.GetPeersByIDs(ctx, store.LockingStrengthShare, accountID, group.Peers)
		if err != nil {
			return err
		}

		for _, id := range group.Peers {
			if _, ok := seenPeers[id]; ok {
				peer, ok := peersMap[id]
				if !ok || peer == nil {
					return status.Errorf(status.InvalidArgument, "peer with ID %s not found", id)
				}

				return status.Errorf(status.AlreadyExists,
					"failed to add route with %s - peer %s from the group %s already has this route",
					getRouteDescriptor(prefix, domains), peer.Name, group.Name)
			}
		}
	}

	return nil
}

func getRouteDescriptor(prefix netip.Prefix, domains domain.List) string {
	if len(domains) > 0 {
		return fmt.Sprintf("domains [%s]", domains.SafeString())
	}
	return fmt.Sprintf("prefix %s", prefix.String())
}

// CreateRoute creates and saves a new route
func (am *DefaultAccountManager) CreateRoute(ctx context.Context, accountID string, prefix netip.Prefix, networkType route.NetworkType, domains domain.List, peerID string, peerGroupIDs []string, description string, netID route.NetID, masquerade bool, metric int, groups, accessControlGroupIDs []string, enabled bool, userID string, keepRoute bool) (*route.Route, error) {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Routes, operations.Create)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	if len(domains) > 0 && prefix.IsValid() {
		return nil, status.Errorf(status.InvalidArgument, "domains and network should not be provided at the same time")
	}

	var newRoute *route.Route
	var updateAccountPeers bool

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		newRoute = &route.Route{
			ID:                  route.ID(xid.New().String()),
			AccountID:           accountID,
			Network:             prefix,
			Domains:             domains,
			KeepRoute:           keepRoute,
			NetID:               netID,
			Description:         description,
			Peer:                peerID,
			PeerGroups:          peerGroupIDs,
			NetworkType:         networkType,
			Masquerade:          masquerade,
			Metric:              metric,
			Enabled:             enabled,
			Groups:              groups,
			AccessControlGroups: accessControlGroupIDs,
		}

		if err = validateRoute(ctx, transaction, accountID, newRoute); err != nil {
			return err
		}

		updateAccountPeers, err = areRouteChangesAffectPeers(ctx, transaction, newRoute)
		if err != nil {
			return err
		}

		if err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		return transaction.SaveRoute(ctx, store.LockingStrengthUpdate, newRoute)
	})
	if err != nil {
		return nil, err
	}

	am.StoreEvent(ctx, userID, string(newRoute.ID), accountID, activity.RouteCreated, newRoute.EventMeta())

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	return newRoute, nil
}

// SaveRoute saves route
func (am *DefaultAccountManager) SaveRoute(ctx context.Context, accountID, userID string, routeToSave *route.Route) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Routes, operations.Update)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	var oldRoute *route.Route
	var oldRouteAffectsPeers bool
	var newRouteAffectsPeers bool

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		if err = validateRoute(ctx, transaction, accountID, routeToSave); err != nil {
			return err
		}

		oldRoute, err = transaction.GetRouteByID(ctx, store.LockingStrengthUpdate, accountID, string(routeToSave.ID))
		if err != nil {
			return err
		}

		oldRouteAffectsPeers, err = areRouteChangesAffectPeers(ctx, transaction, oldRoute)
		if err != nil {
			return err
		}

		newRouteAffectsPeers, err = areRouteChangesAffectPeers(ctx, transaction, routeToSave)
		if err != nil {
			return err
		}
		routeToSave.AccountID = accountID

		if err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		return transaction.SaveRoute(ctx, store.LockingStrengthUpdate, routeToSave)
	})
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, string(routeToSave.ID), accountID, activity.RouteUpdated, routeToSave.EventMeta())

	if oldRouteAffectsPeers || newRouteAffectsPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	return nil
}

// DeleteRoute deletes route with routeID
func (am *DefaultAccountManager) DeleteRoute(ctx context.Context, accountID string, routeID route.ID, userID string) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Routes, operations.Delete)
	if err != nil {
		return status.NewPermissionValidationError(err)
	}
	if !allowed {
		return status.NewPermissionDeniedError()
	}

	var route *route.Route
	var updateAccountPeers bool

	err = am.Store.ExecuteInTransaction(ctx, func(transaction store.Store) error {
		route, err = transaction.GetRouteByID(ctx, store.LockingStrengthUpdate, accountID, string(routeID))
		if err != nil {
			return err
		}

		updateAccountPeers, err = areRouteChangesAffectPeers(ctx, transaction, route)
		if err != nil {
			return err
		}

		if err = transaction.IncrementNetworkSerial(ctx, store.LockingStrengthUpdate, accountID); err != nil {
			return err
		}

		return transaction.DeleteRoute(ctx, store.LockingStrengthUpdate, accountID, string(routeID))
	})

	am.StoreEvent(ctx, userID, string(route.ID), accountID, activity.RouteRemoved, route.EventMeta())

	if updateAccountPeers {
		am.UpdateAccountPeers(ctx, accountID)
	}

	return nil
}

// ListRoutes returns a list of routes from account
func (am *DefaultAccountManager) ListRoutes(ctx context.Context, accountID, userID string) ([]*route.Route, error) {
	allowed, err := am.permissionsManager.ValidateUserPermissions(ctx, accountID, userID, modules.Routes, operations.Read)
	if err != nil {
		return nil, status.NewPermissionValidationError(err)
	}
	if !allowed {
		return nil, status.NewPermissionDeniedError()
	}

	return am.Store.GetAccountRoutes(ctx, store.LockingStrengthShare, accountID)
}

func validateRoute(ctx context.Context, transaction store.Store, accountID string, routeToSave *route.Route) error {
	if routeToSave == nil {
		return status.Errorf(status.InvalidArgument, "route provided is nil")
	}

	if routeToSave.Metric < route.MinMetric || routeToSave.Metric > route.MaxMetric {
		return status.Errorf(status.InvalidArgument, "metric should be between %d and %d", route.MinMetric, route.MaxMetric)
	}

	if utf8.RuneCountInString(string(routeToSave.NetID)) > route.MaxNetIDChar || routeToSave.NetID == "" {
		return status.Errorf(status.InvalidArgument, "identifier should be between 1 and %d", route.MaxNetIDChar)
	}

	if len(routeToSave.Domains) > 0 && routeToSave.Network.IsValid() {
		return status.Errorf(status.InvalidArgument, "domains and network should not be provided at the same time")
	}

	if len(routeToSave.Domains) == 0 && !routeToSave.Network.IsValid() {
		return status.Errorf(status.InvalidArgument, "invalid Prefix")
	}

	if len(routeToSave.Domains) > 0 {
		routeToSave.Network = getPlaceholderIP()
	}

	if routeToSave.Peer != "" && len(routeToSave.PeerGroups) != 0 {
		return status.Errorf(status.InvalidArgument, "peer with ID and peer groups should not be provided at the same time")
	}

	groupsMap, err := validateRouteGroups(ctx, transaction, accountID, routeToSave)
	if err != nil {
		return err
	}

	return checkRoutePrefixOrDomainsExistForPeers(ctx, transaction, accountID, routeToSave, groupsMap)
}

// validateRouteGroups validates the route groups and returns the validated groups map.
func validateRouteGroups(ctx context.Context, transaction store.Store, accountID string, routeToSave *route.Route) (map[string]*types.Group, error) {
	groupsToValidate := slices.Concat(routeToSave.Groups, routeToSave.PeerGroups, routeToSave.AccessControlGroups)
	groupsMap, err := transaction.GetGroupsByIDs(ctx, store.LockingStrengthShare, accountID, groupsToValidate)
	if err != nil {
		return nil, err
	}

	if len(routeToSave.PeerGroups) > 0 {
		if err = validateGroups(routeToSave.PeerGroups, groupsMap); err != nil {
			return nil, err
		}
	}

	if len(routeToSave.AccessControlGroups) > 0 {
		if err = validateGroups(routeToSave.AccessControlGroups, groupsMap); err != nil {
			return nil, err
		}
	}

	if err = validateGroups(routeToSave.Groups, groupsMap); err != nil {
		return nil, err
	}

	return groupsMap, nil
}

func toProtocolRoute(route *route.Route) *proto.Route {
	return &proto.Route{
		ID:          string(route.ID),
		NetID:       string(route.NetID),
		Network:     route.Network.String(),
		Domains:     route.Domains.ToPunycodeList(),
		NetworkType: int64(route.NetworkType),
		Peer:        route.Peer,
		Metric:      int64(route.Metric),
		Masquerade:  route.Masquerade,
		KeepRoute:   route.KeepRoute,
	}
}

func toProtocolRoutes(routes []*route.Route) []*proto.Route {
	protoRoutes := make([]*proto.Route, 0, len(routes))
	for _, r := range routes {
		protoRoutes = append(protoRoutes, toProtocolRoute(r))
	}
	return protoRoutes
}

// getPlaceholderIP returns a placeholder IP address for the route if domains are used
func getPlaceholderIP() netip.Prefix {
	// Using an IP from the documentation range to minimize impact in case older clients try to set a route
	return netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, 0}), 32)
}

func toProtocolRoutesFirewallRules(rules []*types.RouteFirewallRule) []*proto.RouteFirewallRule {
	result := make([]*proto.RouteFirewallRule, len(rules))
	for i := range rules {
		rule := rules[i]
		result[i] = &proto.RouteFirewallRule{
			SourceRanges: rule.SourceRanges,
			Action:       getProtoAction(rule.Action),
			Destination:  rule.Destination,
			Protocol:     getProtoProtocol(rule.Protocol),
			PortInfo:     getProtoPortInfo(rule),
			IsDynamic:    rule.IsDynamic,
			Domains:      rule.Domains.ToPunycodeList(),
			PolicyID:     []byte(rule.PolicyID),
			RouteID:      string(rule.RouteID),
		}
	}

	return result
}

// getProtoDirection converts the direction to proto.RuleDirection.
func getProtoDirection(direction int) proto.RuleDirection {
	if direction == types.FirewallRuleDirectionOUT {
		return proto.RuleDirection_OUT
	}
	return proto.RuleDirection_IN
}

// getProtoAction converts the action to proto.RuleAction.
func getProtoAction(action string) proto.RuleAction {
	if action == string(types.PolicyTrafficActionDrop) {
		return proto.RuleAction_DROP
	}
	return proto.RuleAction_ACCEPT
}

// getProtoProtocol converts the protocol to proto.RuleProtocol.
func getProtoProtocol(protocol string) proto.RuleProtocol {
	switch types.PolicyRuleProtocolType(protocol) {
	case types.PolicyRuleProtocolALL:
		return proto.RuleProtocol_ALL
	case types.PolicyRuleProtocolTCP:
		return proto.RuleProtocol_TCP
	case types.PolicyRuleProtocolUDP:
		return proto.RuleProtocol_UDP
	case types.PolicyRuleProtocolICMP:
		return proto.RuleProtocol_ICMP
	default:
		return proto.RuleProtocol_UNKNOWN
	}
}

// getProtoPortInfo converts the port info to proto.PortInfo.
func getProtoPortInfo(rule *types.RouteFirewallRule) *proto.PortInfo {
	var portInfo proto.PortInfo
	if rule.Port != 0 {
		portInfo.PortSelection = &proto.PortInfo_Port{Port: uint32(rule.Port)}
	} else if portRange := rule.PortRange; portRange.Start != 0 && portRange.End != 0 {
		portInfo.PortSelection = &proto.PortInfo_Range_{
			Range: &proto.PortInfo_Range{
				Start: uint32(portRange.Start),
				End:   uint32(portRange.End),
			},
		}
	}
	return &portInfo
}

// areRouteChangesAffectPeers checks if a given route affects peers by determining
// if it has a routing peer, distribution, or peer groups that include peers.
func areRouteChangesAffectPeers(ctx context.Context, transaction store.Store, route *route.Route) (bool, error) {
	if route.Peer != "" {
		return true, nil
	}

	hasPeers, err := anyGroupHasPeersOrResources(ctx, transaction, route.AccountID, route.Groups)
	if err != nil {
		return false, err
	}

	if hasPeers {
		return true, nil
	}

	return anyGroupHasPeersOrResources(ctx, transaction, route.AccountID, route.PeerGroups)
}

// GetRoutesByPrefixOrDomains return list of routes by account and route prefix
func getRoutesByPrefixOrDomains(ctx context.Context, transaction store.Store, accountID string, prefix netip.Prefix, domains domain.List) ([]*route.Route, error) {
	accountRoutes, err := transaction.GetAccountRoutes(ctx, store.LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	routes := make([]*route.Route, 0)
	for _, r := range accountRoutes {
		dynamic := r.IsDynamic()
		if dynamic && r.Domains.PunycodeString() == domains.PunycodeString() ||
			!dynamic && r.Network.String() == prefix.String() {
			routes = append(routes, r)
		}
	}

	return routes, nil
}
