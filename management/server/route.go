package server

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/rs/xid"
	log "github.com/sirupsen/logrus"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"

	"github.com/netbirdio/netbird/management/domain"
	"github.com/netbirdio/netbird/management/proto"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/status"
	"github.com/netbirdio/netbird/route"
)

// RouteFirewallRule a firewall rule applicable for a routed network.
type RouteFirewallRule struct {
	// SourceRanges IP ranges of the routing peers.
	SourceRanges []string

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

	// isDynamic indicates whether the rule is for DNS routing
	IsDynamic bool
}

// GetRoute gets a route object from account and route IDs
func (am *DefaultAccountManager) GetRoute(ctx context.Context, accountID string, routeID route.ID, userID string) (*route.Route, error) {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
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

// checkRoutePrefixOrDomainsExistForPeers checks if a route with a given prefix exists for a single peer or multiple peer groups.
func (am *DefaultAccountManager) checkRoutePrefixOrDomainsExistForPeers(account *Account, peerID string, routeID route.ID, peerGroupIDs []string, prefix netip.Prefix, domains domain.List) error {
	// routes can have both peer and peer_groups
	routesWithPrefix := account.GetRoutesByPrefixOrDomains(prefix, domains)

	// lets remember all the peers and the peer groups from routesWithPrefix
	seenPeers := make(map[string]bool)
	seenPeerGroups := make(map[string]bool)

	for _, prefixRoute := range routesWithPrefix {
		// we skip route(s) with the same network ID as we want to allow updating of the existing route
		// when creating a new route routeID is newly generated so nothing will be skipped
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
					status.InvalidArgument, "failed to add route with %s - peer group %s doesn't exist",
					getRouteDescriptor(prefix, domains), groupID,
				)
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
				"failed to add route with %s - peer %s already has this route", getRouteDescriptor(prefix, domains), peerID)
		}
	}

	// check that peerGroupIDs are not in any route peerGroups list
	for _, groupID := range peerGroupIDs {
		group := account.GetGroup(groupID) // we validated the group existence before entering this function, no need to check again.

		if _, ok := seenPeerGroups[groupID]; ok {
			return status.Errorf(
				status.AlreadyExists, "failed to add route with %s - peer group %s already has this route",
				getRouteDescriptor(prefix, domains), group.Name)
		}

		// check that the peers from peerGroupIDs groups are not the same peers we saw in routesWithPrefix
		for _, id := range group.Peers {
			if _, ok := seenPeers[id]; ok {
				peer := account.GetPeer(id)
				if peer == nil {
					return status.Errorf(status.InvalidArgument, "peer with ID %s not found", peerID)
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

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return nil, err
	}

	if len(domains) > 0 && prefix.IsValid() {
		return nil, status.Errorf(status.InvalidArgument, "domains and network should not be provided at the same time")
	}

	if len(domains) == 0 && !prefix.IsValid() {
		return nil, status.Errorf(status.InvalidArgument, "invalid Prefix")
	}

	if len(domains) > 0 {
		prefix = getPlaceholderIP()
	}

	if peerID != "" && len(peerGroupIDs) != 0 {
		return nil, status.Errorf(
			status.InvalidArgument,
			"peer with ID %s and peers group %s should not be provided at the same time",
			peerID, peerGroupIDs)
	}

	var newRoute route.Route
	newRoute.ID = route.ID(xid.New().String())

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

	err = am.checkRoutePrefixOrDomainsExistForPeers(account, peerID, newRoute.ID, peerGroupIDs, prefix, domains)
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
	newRoute.Network = prefix
	newRoute.Domains = domains
	newRoute.NetworkType = networkType
	newRoute.Description = description
	newRoute.NetID = netID
	newRoute.Masquerade = masquerade
	newRoute.Metric = metric
	newRoute.Enabled = enabled
	newRoute.Groups = groups
	newRoute.KeepRoute = keepRoute
	newRoute.AccessControlGroups = accessControlGroupIDs

	if account.Routes == nil {
		account.Routes = make(map[route.ID]*route.Route)
	}

	account.Routes[newRoute.ID] = &newRoute

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(ctx, account); err != nil {
		return nil, err
	}

	am.updateAccountPeers(ctx, account)

	am.StoreEvent(ctx, userID, string(newRoute.ID), accountID, activity.RouteCreated, newRoute.EventMeta())

	return &newRoute, nil
}

// SaveRoute saves route
func (am *DefaultAccountManager) SaveRoute(ctx context.Context, accountID, userID string, routeToSave *route.Route) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	if routeToSave == nil {
		return status.Errorf(status.InvalidArgument, "route provided is nil")
	}

	if routeToSave.Metric < route.MinMetric || routeToSave.Metric > route.MaxMetric {
		return status.Errorf(status.InvalidArgument, "metric should be between %d and %d", route.MinMetric, route.MaxMetric)
	}

	if utf8.RuneCountInString(string(routeToSave.NetID)) > route.MaxNetIDChar || routeToSave.NetID == "" {
		return status.Errorf(status.InvalidArgument, "identifier should be between 1 and %d", route.MaxNetIDChar)
	}

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return err
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

	err = am.checkRoutePrefixOrDomainsExistForPeers(account, routeToSave.Peer, routeToSave.ID, routeToSave.Copy().PeerGroups, routeToSave.Network, routeToSave.Domains)
	if err != nil {
		return err
	}

	err = validateGroups(routeToSave.Groups, account.Groups)
	if err != nil {
		return err
	}

	account.Routes[routeToSave.ID] = routeToSave

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(ctx, account); err != nil {
		return err
	}

	am.updateAccountPeers(ctx, account)

	am.StoreEvent(ctx, userID, string(routeToSave.ID), accountID, activity.RouteUpdated, routeToSave.EventMeta())

	return nil
}

// DeleteRoute deletes route with routeID
func (am *DefaultAccountManager) DeleteRoute(ctx context.Context, accountID string, routeID route.ID, userID string) error {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
	if err != nil {
		return err
	}

	routy := account.Routes[routeID]
	if routy == nil {
		return status.Errorf(status.NotFound, "route with ID %s doesn't exist", routeID)
	}
	delete(account.Routes, routeID)

	account.Network.IncSerial()
	if err = am.Store.SaveAccount(ctx, account); err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, string(routy.ID), accountID, activity.RouteRemoved, routy.EventMeta())

	am.updateAccountPeers(ctx, account)

	return nil
}

// ListRoutes returns a list of routes from account
func (am *DefaultAccountManager) ListRoutes(ctx context.Context, accountID, userID string) ([]*route.Route, error) {
	unlock := am.Store.AcquireWriteLockByUID(ctx, accountID)
	defer unlock()

	account, err := am.Store.GetAccount(ctx, accountID)
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
		Domains:     route.Domains.ToPunycodeList(),
		NetworkType: int64(route.NetworkType),
		Peer:        route.Peer,
		Metric:      int64(route.Metric),
		Masquerade:  route.Masquerade,
		KeepRoute:   route.KeepRoute,
	}
}

func toProtocolRoutes(routes []*route.Route) []*proto.Route {
	protoRoutes := make([]*proto.Route, 0)
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

// getPeerRoutesFirewallRules gets the routes firewall rules associated with a routing peer ID for the account.
func (a *Account) getPeerRoutesFirewallRules(ctx context.Context, peerID string, validatedPeersMap map[string]struct{}) []*RouteFirewallRule {
	routesFirewallRules := make([]*RouteFirewallRule, 0, len(a.Routes))

	enabledRoutes, _ := a.getRoutingPeerRoutes(ctx, peerID)
	for _, route := range enabledRoutes {
		// If no access control groups are specified, accept all traffic.
		if len(route.AccessControlGroups) == 0 {
			defaultPermit := getDefaultPermit(route)
			routesFirewallRules = append(routesFirewallRules, defaultPermit...)
			continue
		}

		policies := getAllRoutePoliciesFromGroups(a, route.AccessControlGroups)
		for _, policy := range policies {
			if !policy.Enabled {
				continue
			}

			for _, rule := range policy.Rules {
				if !rule.Enabled {
					continue
				}

				distributionGroupPeers, _ := a.getAllPeersFromGroups(ctx, route.Groups, peerID, nil, validatedPeersMap)
				rules := generateRouteFirewallRules(ctx, route, rule, distributionGroupPeers, firewallRuleDirectionIN)
				routesFirewallRules = append(routesFirewallRules, rules...)
			}
		}
	}

	return routesFirewallRules
}

func getDefaultPermit(route *route.Route) []*RouteFirewallRule {
	var rules []*RouteFirewallRule

	sources := []string{"0.0.0.0/0"}
	if route.Network.Addr().Is6() {
		sources = []string{"::/0"}
	}
	rule := RouteFirewallRule{
		SourceRanges: sources,
		Direction:    firewallRuleDirectionIN,
		Action:       string(PolicyTrafficActionAccept),
		Destination:  route.Network.String(),
		Protocol:     string(PolicyRuleProtocolALL),
		NetworkType:  int(route.NetworkType),
		IsDynamic:    route.IsDynamic(),
	}

	rules = append(rules, &rule)

	// dynamic routes always contain an IPv4 placeholder as destination, hence we must add IPv6 rules additionally
	if route.IsDynamic() {
		ruleV6 := rule
		ruleV6.SourceRanges = []string{"::/0"}
		rules = append(rules, &ruleV6)
	}

	return rules
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
func generateRouteFirewallRules(ctx context.Context, route *route.Route, rule *PolicyRule, groupPeers []*nbpeer.Peer, direction int) []*RouteFirewallRule {
	rulesExists := make(map[string]struct{})
	rules := make([]*RouteFirewallRule, 0)

	sourceRanges := make([]string, 0, len(groupPeers))
	for _, peer := range groupPeers {
		if peer == nil {
			continue
		}
		sourceRanges = append(sourceRanges, fmt.Sprintf(AllowedIPsFormat, peer.IP))
	}

	baseRule := RouteFirewallRule{
		SourceRanges: sourceRanges,
		Direction:    direction,
		Action:       string(rule.Action),
		Destination:  route.Network.String(),
		Protocol:     string(rule.Protocol),
		NetworkType:  int(route.NetworkType),
		IsDynamic:    route.IsDynamic(),
	}

	// generate rule for port range
	if len(rule.Ports) == 0 {
		rules = append(rules, generateRulesWithPortRanges(baseRule, rule, rulesExists)...)
	} else {
		rules = append(rules, generateRulesWithPorts(ctx, baseRule, rule, rulesExists)...)

	}

	// TODO: generate IPv6 rules for dynamic routes

	return rules
}

// generateRuleIDBase generates the base rule ID for checking duplicates.
func generateRuleIDBase(rule *PolicyRule, baseRule RouteFirewallRule) string {
	return rule.ID + strings.Join(baseRule.SourceRanges, ",") + strconv.Itoa(firewallRuleDirectionIN) + baseRule.Protocol + baseRule.Action
}

// generateRulesForPeer generates rules for a given peer based on ports and port ranges.
func generateRulesWithPortRanges(baseRule RouteFirewallRule, rule *PolicyRule, rulesExists map[string]struct{}) []*RouteFirewallRule {
	rules := make([]*RouteFirewallRule, 0)

	ruleIDBase := generateRuleIDBase(rule, baseRule)
	if len(rule.Ports) == 0 {
		if len(rule.PortRanges) == 0 {
			if _, ok := rulesExists[ruleIDBase]; !ok {
				rulesExists[ruleIDBase] = struct{}{}
				rules = append(rules, &baseRule)
			}
		} else {
			for _, portRange := range rule.PortRanges {
				ruleID := fmt.Sprintf("%s%d-%d", ruleIDBase, portRange.Start, portRange.End)
				if _, ok := rulesExists[ruleID]; !ok {
					rulesExists[ruleID] = struct{}{}
					pr := baseRule
					pr.PortRange = portRange
					rules = append(rules, &pr)
				}
			}
		}
		return rules
	}

	return rules
}

// generateRulesWithPorts generates rules when specific ports are provided.
func generateRulesWithPorts(ctx context.Context, baseRule RouteFirewallRule, rule *PolicyRule, rulesExists map[string]struct{}) []*RouteFirewallRule {
	rules := make([]*RouteFirewallRule, 0)
	ruleIDBase := generateRuleIDBase(rule, baseRule)

	for _, port := range rule.Ports {
		ruleID := ruleIDBase + port
		if _, ok := rulesExists[ruleID]; ok {
			continue
		}
		rulesExists[ruleID] = struct{}{}

		pr := baseRule
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			log.WithContext(ctx).Errorf("failed to parse port %s for rule: %s", port, rule.ID)
			continue
		}

		pr.Port = uint16(p)
		rules = append(rules, &pr)
	}

	return rules
}

func toProtocolRoutesFirewallRules(rules []*RouteFirewallRule) []*proto.RouteFirewallRule {
	result := make([]*proto.RouteFirewallRule, len(rules))
	for i := range rules {
		rule := rules[i]
		result[i] = &proto.RouteFirewallRule{
			SourceRanges: rule.SourceRanges,
			Direction:    getProtoDirection(rule.Direction),
			Action:       getProtoAction(rule.Action),
			NetworkType:  getProtoNetworkType(rule.NetworkType),
			Destination:  rule.Destination,
			Protocol:     getProtoProtocol(rule.Protocol),
			PortInfo:     getProtoPortInfo(rule),
			IsDynamic:    rule.IsDynamic,
		}
	}

	return result
}

// getProtoDirection converts the direction to proto.RuleDirection.
func getProtoDirection(direction int) proto.RuleDirection {
	if direction == firewallRuleDirectionOUT {
		return proto.RuleDirection_OUT
	}
	return proto.RuleDirection_IN
}

// getProtoAction converts the action to proto.RuleAction.
func getProtoAction(action string) proto.RuleAction {
	if action == string(PolicyTrafficActionDrop) {
		return proto.RuleAction_DROP
	}
	return proto.RuleAction_ACCEPT
}

// getProtoProtocol converts the protocol to proto.RuleProtocol.
func getProtoProtocol(protocol string) proto.RuleProtocol {
	switch PolicyRuleProtocolType(protocol) {
	case PolicyRuleProtocolALL:
		return proto.RuleProtocol_ALL
	case PolicyRuleProtocolTCP:
		return proto.RuleProtocol_TCP
	case PolicyRuleProtocolUDP:
		return proto.RuleProtocol_UDP
	case PolicyRuleProtocolICMP:
		return proto.RuleProtocol_ICMP
	default:
		return proto.RuleProtocol_UNKNOWN
	}
}

// getProtoNetworkType converts the network type to proto.RouteFirewallRule_NetworkType.
func getProtoNetworkType(networkType int) proto.RouteFirewallRule_NetworkType {
	switch route.NetworkType(networkType) {
	case route.IPv4Network:
		return proto.RouteFirewallRule_IPV4
	case route.IPv6Network:
		return proto.RouteFirewallRule_IPV6
	case route.DomainNetwork:
		return proto.RouteFirewallRule_Domain
	default:
		return proto.RouteFirewallRule_UNKNOWN
	}
}

// getProtoPortInfo converts the port info to proto.PortInfo.
func getProtoPortInfo(rule *RouteFirewallRule) *proto.PortInfo {
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
