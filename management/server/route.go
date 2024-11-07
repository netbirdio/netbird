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

	// Action of the traffic when the rule is applicable
	Action string

	// Destination a network prefix for the routed traffic
	Destination string

	// Protocol of the traffic
	Protocol string

	// Port of the traffic
	Port uint16

	// PortRange represents the range of ports for a firewall rule
	PortRange RulePortRange

	// isDynamic indicates whether the rule is for DNS routing
	IsDynamic bool
}

// GetRoute gets a route object from account and route IDs
func (am *DefaultAccountManager) GetRoute(ctx context.Context, accountID string, routeID route.ID, userID string) (*route.Route, error) {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return nil, status.NewAdminPermissionError()
	}

	return am.Store.GetRouteByID(ctx, LockingStrengthShare, accountID, string(routeID))
}

// GetRoutesByPrefixOrDomains return list of routes by account and route prefix
func (am *DefaultAccountManager) GetRoutesByPrefixOrDomains(ctx context.Context, accountID string, prefix netip.Prefix, domains domain.List) ([]*route.Route, error) {
	accountRoutes, err := am.Store.GetAccountRoutes(ctx, LockingStrengthShare, accountID)
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

// checkRoutePrefixOrDomainsExistForPeers checks if a route with a given prefix exists for a single peer or multiple peer groups.
func (am *DefaultAccountManager) checkRoutePrefixOrDomainsExistForPeers(ctx context.Context, accountID, peerID string, routeID route.ID, peerGroupIDs []string, prefix netip.Prefix, domains domain.List) error {
	// routes can have both peer and peer_groups
	routesWithPrefix, err := am.GetRoutesByPrefixOrDomains(ctx, accountID, prefix, domains)
	if err != nil {
		return err
	}

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

			group, err := am.Store.GetGroupByID(context.Background(), LockingStrengthShare, accountID, groupID)
			if err != nil || group == nil {
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
		peer, err := am.Store.GetPeerByID(context.Background(), LockingStrengthShare, accountID, peerID)
		if err != nil || peer == nil {
			return status.Errorf(status.InvalidArgument, "peer with ID %s not found", peerID)
		}

		if _, ok := seenPeers[peerID]; ok {
			return status.Errorf(status.AlreadyExists,
				"failed to add route with %s - peer %s already has this route", getRouteDescriptor(prefix, domains), peerID)
		}
	}

	// check that peerGroupIDs are not in any route peerGroups list
	for _, groupID := range peerGroupIDs {
		// we validated the group existence before entering this function, no need to check again.
		group, err := am.Store.GetGroupByID(context.Background(), LockingStrengthShare, accountID, groupID)
		if err != nil || group == nil {
			return status.Errorf(status.InvalidArgument, "group with ID %s not found", peerID)
		}

		if _, ok := seenPeerGroups[groupID]; ok {
			return status.Errorf(
				status.AlreadyExists, "failed to add route with %s - peer group %s already has this route",
				getRouteDescriptor(prefix, domains), group.Name)
		}

		// check that the peers from peerGroupIDs groups are not the same peers we saw in routesWithPrefix
		for _, id := range group.Peers {
			if _, ok := seenPeers[id]; ok {
				peer, err := am.Store.GetPeerByID(context.Background(), LockingStrengthShare, accountID, peerID)
				if err != nil {
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
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	// Do not allow non-Linux peers
	if peerID != "" {
		peer, err := am.Store.GetPeerByID(ctx, LockingStrengthShare, accountID, peerID)
		if err != nil {
			return nil, err
		}

		if peer.Meta.GoOS != "linux" {
			return nil, status.Errorf(status.InvalidArgument, "non-linux peers are not supported as network routes")
		}
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
	newRoute.AccountID = accountID

	accountGroups, err := am.Store.GetAccountGroups(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return nil, err
	}

	if len(peerGroupIDs) > 0 {
		err = validateGroups(peerGroupIDs, accountGroups)
		if err != nil {
			return nil, err
		}
	}

	if len(accessControlGroupIDs) > 0 {
		err = validateGroups(accessControlGroupIDs, accountGroups)
		if err != nil {
			return nil, err
		}
	}

	err = am.checkRoutePrefixOrDomainsExistForPeers(ctx, accountID, peerID, newRoute.ID, peerGroupIDs, prefix, domains)
	if err != nil {
		return nil, err
	}

	if metric < route.MinMetric || metric > route.MaxMetric {
		return nil, status.Errorf(status.InvalidArgument, "metric should be between %d and %d", route.MinMetric, route.MaxMetric)
	}

	if utf8.RuneCountInString(string(netID)) > route.MaxNetIDChar || netID == "" {
		return nil, status.Errorf(status.InvalidArgument, "identifier should be between 1 and %d", route.MaxNetIDChar)
	}

	err = validateGroups(groups, accountGroups)
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

	updateAccountPeers, err := am.areRouteChangesAffectPeers(ctx, &newRoute)
	if err != nil {
		return nil, err
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		if err = transaction.IncrementNetworkSerial(ctx, LockingStrengthUpdate, accountID); err != nil {
			return fmt.Errorf(errNetworkSerialIncrementFmt, err)
		}

		err = transaction.SaveRoute(ctx, LockingStrengthUpdate, &newRoute)
		if err != nil {
			return fmt.Errorf("failed to create route: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	am.StoreEvent(ctx, userID, string(newRoute.ID), accountID, activity.RouteCreated, newRoute.EventMeta())

	if updateAccountPeers {
		am.updateAccountPeers(ctx, accountID)
	}

	return &newRoute, nil
}

// SaveRoute saves route
func (am *DefaultAccountManager) SaveRoute(ctx context.Context, accountID, userID string, routeToSave *route.Route) error {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	if routeToSave == nil {
		return status.Errorf(status.InvalidArgument, "route provided is nil")
	}

	if routeToSave.Metric < route.MinMetric || routeToSave.Metric > route.MaxMetric {
		return status.Errorf(status.InvalidArgument, "metric should be between %d and %d", route.MinMetric, route.MaxMetric)
	}

	if utf8.RuneCountInString(string(routeToSave.NetID)) > route.MaxNetIDChar || routeToSave.NetID == "" {
		return status.Errorf(status.InvalidArgument, "identifier should be between 1 and %d", route.MaxNetIDChar)
	}

	oldRoute, err := am.Store.GetRouteByID(ctx, LockingStrengthShare, accountID, string(routeToSave.ID))
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

	// Do not allow non-Linux peers
	if routeToSave.Peer != "" {
		peer, err := am.Store.GetPeerByID(ctx, LockingStrengthShare, accountID, routeToSave.Peer)
		if err != nil {
			return err
		}

		if peer.Meta.GoOS != "linux" {
			return status.Errorf(status.InvalidArgument, "non-linux peers are not supported as network routes")
		}
	}

	groups, err := am.Store.GetAccountGroups(ctx, LockingStrengthShare, accountID)
	if err != nil {
		return err
	}

	if len(routeToSave.PeerGroups) > 0 {
		err = validateGroups(routeToSave.PeerGroups, groups)
		if err != nil {
			return err
		}
	}

	if len(routeToSave.AccessControlGroups) > 0 {
		err = validateGroups(routeToSave.AccessControlGroups, groups)
		if err != nil {
			return err
		}
	}

	err = am.checkRoutePrefixOrDomainsExistForPeers(ctx, accountID, routeToSave.Peer, routeToSave.ID, routeToSave.Copy().PeerGroups, routeToSave.Network, routeToSave.Domains)
	if err != nil {
		return err
	}

	err = validateGroups(routeToSave.Groups, groups)
	if err != nil {
		return err
	}

	oldRouteAffectsPeers, err := am.areRouteChangesAffectPeers(ctx, oldRoute)
	if err != nil {
		return err
	}

	newRouteAffectsPeers, err := am.areRouteChangesAffectPeers(ctx, routeToSave)
	if err != nil {
		return err
	}
	routeToSave.AccountID = accountID

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		if err = transaction.IncrementNetworkSerial(ctx, LockingStrengthUpdate, accountID); err != nil {
			return fmt.Errorf(errNetworkSerialIncrementFmt, err)
		}

		err = transaction.SaveRoute(ctx, LockingStrengthUpdate, routeToSave)
		if err != nil {
			return fmt.Errorf("failed to save route: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}

	am.StoreEvent(ctx, userID, string(routeToSave.ID), accountID, activity.RouteUpdated, routeToSave.EventMeta())

	if oldRouteAffectsPeers || newRouteAffectsPeers {
		am.updateAccountPeers(ctx, accountID)
	}

	return nil
}

// DeleteRoute deletes route with routeID
func (am *DefaultAccountManager) DeleteRoute(ctx context.Context, accountID string, routeID route.ID, userID string) error {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return err
	}

	if user.AccountID != accountID {
		return status.NewUserNotPartOfAccountError()
	}

	route, err := am.Store.GetRouteByID(ctx, LockingStrengthShare, accountID, string(routeID))
	if err != nil {
		return err
	}

	updateAccountPeers, err := am.areRouteChangesAffectPeers(ctx, route)
	if err != nil {
		return err
	}

	err = am.Store.ExecuteInTransaction(ctx, func(transaction Store) error {
		if err = transaction.IncrementNetworkSerial(ctx, LockingStrengthUpdate, accountID); err != nil {
			return fmt.Errorf(errNetworkSerialIncrementFmt, err)
		}

		if err = transaction.DeleteRoute(ctx, LockingStrengthUpdate, accountID, string(routeID)); err != nil {
			return fmt.Errorf("failed to delete route: %w", err)
		}
		return nil
	})

	am.StoreEvent(ctx, userID, string(route.ID), accountID, activity.RouteRemoved, route.EventMeta())

	if updateAccountPeers {
		am.updateAccountPeers(ctx, accountID)
	}

	return nil
}

// ListRoutes returns a list of routes from account
func (am *DefaultAccountManager) ListRoutes(ctx context.Context, accountID, userID string) ([]*route.Route, error) {
	user, err := am.Store.GetUserByUserID(ctx, LockingStrengthShare, userID)
	if err != nil {
		return nil, err
	}

	if user.AccountID != accountID {
		return nil, status.NewUserNotPartOfAccountError()
	}

	if user.IsRegularUser() {
		return nil, status.NewAdminPermissionError()
	}

	return am.Store.GetAccountRoutes(ctx, LockingStrengthShare, accountID)
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
		Action:       string(PolicyTrafficActionAccept),
		Destination:  route.Network.String(),
		Protocol:     string(PolicyRuleProtocolALL),
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
		Action:       string(rule.Action),
		Destination:  route.Network.String(),
		Protocol:     string(rule.Protocol),
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
			Action:       getProtoAction(rule.Action),
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

// areRouteChangesAffectPeers checks if a given route affects peers by determining
// if it has a routing peer, distribution, or peer groups that include peers.
func (am *DefaultAccountManager) areRouteChangesAffectPeers(ctx context.Context, route *route.Route) (bool, error) {
	if route.Peer != "" {
		return true, nil
	}

	hasPeers, err := am.anyGroupHasPeers(ctx, route.AccountID, route.Groups)
	if err != nil {
		return false, err
	}

	if hasPeers {
		return true, nil
	}

	return am.anyGroupHasPeers(ctx, route.AccountID, route.PeerGroups)
}
