package server

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/route"
)

// RouteFirewallRule a firewall rule applicable for a routed network.
type RouteFirewallRule struct {
	// PeerIP IP address of the routing peer.
	PeerIP string

	// Direction of the traffic
	Direction int

	// Action of the traffic when the rule is applicable
	Action string

	// Destination a network prefix for the routed traffic
	Destination string

	// Protocol of the traffic
	Protocol string

	// NetworkType string
	NetworkType int

	// Port of the traffic
	Port uint16

	// PortRange represents the range of ports for a firewall rule
	PortRange RulePortRange
}

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
func (am *DefaultAccountManager) CreateRoute(accountID, network, peerID string, peerGroupIDs []string, description string, netID route.NetID, masquerade bool, metric int, groups []string, accessControlGroupIDs []string, enabled bool, userID string) (*route.Route, error) {
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

	if len(accessControlGroupIDs) > 0 {
		err = validateGroups(accessControlGroupIDs, account.Groups)
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
	newRoute.AccessControlGroups = accessControlGroupIDs

	if account.Routes == nil {
		account.Routes = make(map[route.ID]*route.Route)
	}

	account.Routes[newRoute.ID] = &newRoute

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

	if len(routeToSave.PeerGroups) > 0 {
		err = validateGroups(routeToSave.PeerGroups, account.Groups)
		if err != nil {
			return err
		}
	}

	if len(routeToSave.AccessControlGroups) > 0 {
		err = validateGroups(routeToSave.AccessControlGroups, account.Groups)
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

	account.Routes[routeToSave.ID] = routeToSave

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

// getPeerRoutesFirewallRules gets the routes firewall rules associated with a routing peer ID for the account.
func (a *Account) getPeerRoutesFirewallRules(peerID string, validatedPeersMap map[string]struct{}) []*RouteFirewallRule {
	routesFirewallRules := make([]*RouteFirewallRule, 0, len(a.Routes))

	enabledRoutes, _ := a.getRoutingPeerRoutes(peerID)
	for _, route := range enabledRoutes {
		policies := getAllRoutePoliciesFromGroups(a, route.AccessControlGroups)
		for _, policy := range policies {
			if !policy.Enabled {
				continue
			}

			for _, rule := range policy.Rules {
				if !rule.Enabled {
					continue
				}

				distributionGroupPeers, _ := getAllPeersFromGroups(a, route.Groups, peerID, nil, validatedPeersMap)
				rules := generateRouteFirewallRules(route, rule, distributionGroupPeers, firewallRuleDirectionIN)
				routesFirewallRules = append(routesFirewallRules, rules...)
			}
		}
	}

	return routesFirewallRules
}

// getAllRoutePoliciesFromGroups retrieves route policies associated with the specified access control groups
// and returns a list of policies that have rules with destinations matching the specified groups.
func getAllRoutePoliciesFromGroups(account *Account, accessControlGroups []string) []*Policy {
	routePolicies := make([]*Policy, 0)
	for _, groupID := range accessControlGroups {
		group, ok := account.Groups[groupID]
		if !ok {
			continue
		}

		for _, policy := range account.Policies {
			for _, rule := range policy.Rules {
				exist := slices.ContainsFunc(rule.Destinations, func(groupID string) bool {
					return groupID == group.ID
				})
				if exist {
					routePolicies = append(routePolicies, policy)
					continue
				}
			}
		}
	}

	return routePolicies
}

// generateRouteFirewallRules generates a list of firewall rules for a given route.
func generateRouteFirewallRules(route *route.Route, rule *PolicyRule, groupPeers []*nbpeer.Peer, direction int) []*RouteFirewallRule {
	rulesExists := make(map[string]struct{})
	rules := make([]*RouteFirewallRule, 0)

	for _, peer := range groupPeers {
		if peer == nil {
			continue
		}

		rr := RouteFirewallRule{
			PeerIP:      peer.IP.String(),
			Direction:   direction,
			Action:      string(rule.Action),
			Destination: route.Network.String(),
			Protocol:    string(rule.Protocol),
			NetworkType: int(route.NetworkType),
		}

		ruleID := rule.ID + rr.PeerIP + strconv.Itoa(firewallRuleDirectionIN) +
			rr.Protocol + rr.Action + strings.Join(rule.Ports, ",")
		if _, ok := rulesExists[ruleID]; ok {
			continue
		}
		rulesExists[ruleID] = struct{}{}

		if len(rule.Ports) == 0 {
			if len(rule.PortRanges) == 0 {
				rules = append(rules, &rr)
				continue
			}

			for _, portRange := range rule.PortRanges {
				pr := rr
				pr.PortRange = portRange
				rules = append(rules, &pr)
			}
			continue
		}

		for _, port := range rule.Ports {
			pr := rr // clone rule and add set new port

			p, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				log.Errorf("failed to parse port %s for rule: %s", port, rule.ID)
				continue
			}

			pr.Port = uint16(p)
			rules = append(rules, &pr)
		}

	}

	return rules
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

func toProtocolRoutesFirewallRules(update []*RouteFirewallRule) []*proto.RouteFirewallRule {
	result := make([]*proto.RouteFirewallRule, len(update))
	for i := range update {
		direction := proto.RuleDirection_IN
		if update[i].Direction == firewallRuleDirectionOUT {
			direction = proto.RuleDirection_OUT
		}
		action := proto.RuleAction_ACCEPT
		if update[i].Action == string(PolicyTrafficActionDrop) {
			action = proto.RuleAction_DROP
		}

		protocol := proto.RuleProtocol_UNKNOWN
		switch PolicyRuleProtocolType(update[i].Protocol) {
		case PolicyRuleProtocolALL:
			protocol = proto.RuleProtocol_ALL
		case PolicyRuleProtocolTCP:
			protocol = proto.RuleProtocol_TCP
		case PolicyRuleProtocolUDP:
			protocol = proto.RuleProtocol_UDP
		case PolicyRuleProtocolICMP:
			protocol = proto.RuleProtocol_ICMP
		}

		networkType := proto.RouteFirewallRule_IPV4
		if route.NetworkType(update[i].NetworkType) == route.IPv6Network {
			networkType = proto.RouteFirewallRule_IPV6
		}

		var portInfo proto.PortInfo
		if update[i].Port != 0 {
			portInfo.PortSelection = &proto.PortInfo_Port{Port: uint32(update[i].Port)}
		} else {
			if portRange := update[i].PortRange; portRange.Start != 0 && portRange.End != 0 {
				portInfo.PortSelection = &proto.PortInfo_Range_{
					Range: &proto.PortInfo_Range{
						Start: uint32(portRange.Start),
						End:   uint32(portRange.End),
					},
				}
			}
		}

		result[i] = &proto.RouteFirewallRule{
			PeerIP:      update[i].PeerIP,
			Direction:   direction,
			Action:      action,
			NetworkType: networkType,
			Destination: update[i].Destination,
			Protocol:    protocol,
			PortInfo:    &portInfo,
		}
	}
	return result
}
