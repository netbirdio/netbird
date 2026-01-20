package types

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/netbirdio/netbird/client/ssh/auth"
	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

type NetworkMapComponents struct {
	PeerID string
	Serial uint64

	Network          *Network
	AccountSettings  *AccountSettingsInfo
	DNSSettings      *DNSSettings
	CustomZoneDomain string

	Peers               map[string]*nbpeer.Peer
	Groups              map[string]*Group
	Policies            []*Policy
	Routes              []*route.Route
	NameServerGroups    []*nbdns.NameServerGroup
	AllDNSRecords []nbdns.SimpleRecord
	AccountZones  []nbdns.CustomZone
	ResourcePoliciesMap map[string][]*Policy
	RoutersMap          map[string]map[string]*routerTypes.NetworkRouter
	NetworkResources    []*resourceTypes.NetworkResource

	GroupIDToUserIDs   map[string][]string
	AllowedUserIDs     map[string]struct{}
	PostureFailedPeers map[string]map[string]struct{}
}

type AccountSettingsInfo struct {
	PeerLoginExpirationEnabled      bool
	PeerLoginExpiration             time.Duration
	PeerInactivityExpirationEnabled bool
	PeerInactivityExpiration        time.Duration
}

func (c *NetworkMapComponents) GetPeerInfo(peerID string) *nbpeer.Peer {
	return c.Peers[peerID]
}

func (c *NetworkMapComponents) GetGroupInfo(groupID string) *Group {
	return c.Groups[groupID]
}

func (c *NetworkMapComponents) IsPeerInGroup(peerID, groupID string) bool {
	group := c.GetGroupInfo(groupID)
	if group == nil {
		return false
	}

	return slices.Contains(group.Peers, peerID)
}

func (c *NetworkMapComponents) GetPeerGroups(peerID string) map[string]struct{} {
	groups := make(map[string]struct{})
	for groupID, group := range c.Groups {
		if slices.Contains(group.Peers, peerID) {
			groups[groupID] = struct{}{}
		}
	}
	return groups
}

func (c *NetworkMapComponents) ValidatePostureChecksOnPeer(peerID string, postureCheckIDs []string) bool {
	_, exists := c.Peers[peerID]
	if !exists {
		return false
	}
	if len(postureCheckIDs) == 0 {
		return true
	}
	for _, checkID := range postureCheckIDs {
		if failedPeers, exists := c.PostureFailedPeers[checkID]; exists {
			if _, failed := failedPeers[peerID]; failed {
				return false
			}
		}
	}
	return true
}

type NetworkMapCalculator struct {
	components *NetworkMapComponents
}

func NewNetworkMapCalculator(components *NetworkMapComponents) *NetworkMapCalculator {
	return &NetworkMapCalculator{
		components: components,
	}
}

func CalculateNetworkMapFromComponents(ctx context.Context, components *NetworkMapComponents) *NetworkMap {
	calculator := NewNetworkMapCalculator(components)
	return calculator.Calculate(ctx)
}

func (calc *NetworkMapCalculator) Calculate(ctx context.Context) *NetworkMap {
	targetPeerID := calc.components.PeerID

	peerGroups := calc.components.GetPeerGroups(targetPeerID)

	aclPeers, firewallRules, authorizedUsers, sshEnabled := calc.getPeerConnectionResources(ctx, targetPeerID)

	peersToConnect, expiredPeers := calc.filterPeersByLoginExpiration(aclPeers)

	routesUpdate := calc.getRoutesToSync(ctx, targetPeerID, peersToConnect, peerGroups)
	routesFirewallRules := calc.getPeerRoutesFirewallRules(ctx, targetPeerID)

	isRouter, networkResourcesRoutes, sourcePeers := calc.getNetworkResourcesRoutesToSync(ctx, targetPeerID)
	var networkResourcesFirewallRules []*RouteFirewallRule
	if isRouter {
		networkResourcesFirewallRules = calc.getPeerNetworkResourceFirewallRules(ctx, targetPeerID, networkResourcesRoutes)
	}

	peersToConnectIncludingRouters := calc.addNetworksRoutingPeers(
		networkResourcesRoutes,
		targetPeerID,
		peersToConnect,
		expiredPeers,
		isRouter,
		sourcePeers,
	)

	dnsManagementStatus := calc.getPeerDNSManagementStatus(targetPeerID)
	dnsUpdate := nbdns.Config{
		ServiceEnable: dnsManagementStatus,
	}

	if dnsManagementStatus {
		var customZones []nbdns.CustomZone

		if calc.components.CustomZoneDomain != "" && len(calc.components.AllDNSRecords) > 0 {
			customZones = append(customZones, nbdns.CustomZone{
				Domain:  calc.components.CustomZoneDomain,
				Records: calc.components.AllDNSRecords,
			})
		}

		customZones = append(customZones, calc.components.AccountZones...)

		dnsUpdate.CustomZones = customZones
		dnsUpdate.NameServerGroups = calc.getPeerNSGroups(targetPeerID)
	}

	return &NetworkMap{
		Peers:               peersToConnectIncludingRouters,
		Network:             calc.components.Network.Copy(),
		Routes:              append(networkResourcesRoutes, routesUpdate...),
		DNSConfig:           dnsUpdate,
		OfflinePeers:        expiredPeers,
		FirewallRules:       firewallRules,
		RoutesFirewallRules: append(networkResourcesFirewallRules, routesFirewallRules...),
		AuthorizedUsers:     authorizedUsers,
		EnableSSH:           sshEnabled,
	}
}

func (calc *NetworkMapCalculator) getPeerConnectionResources(ctx context.Context, targetPeerID string) ([]*nbpeer.Peer, []*FirewallRule, map[string]map[string]struct{}, bool) {
	targetPeer := calc.components.GetPeerInfo(targetPeerID)
	if targetPeer == nil {
		return nil, nil, nil, false
	}

	generateResources, getAccumulatedResources := calc.connResourcesGenerator(ctx, targetPeer)
	authorizedUsers := make(map[string]map[string]struct{})
	sshEnabled := false

	for _, policy := range calc.components.Policies {
		if !policy.Enabled {
			continue
		}

		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			var sourcePeers, destinationPeers []*nbpeer.Peer
			var peerInSources, peerInDestinations bool

			if rule.SourceResource.Type == ResourceTypePeer && rule.SourceResource.ID != "" {
				sourcePeers, peerInSources = calc.getPeerFromResource(rule.SourceResource, targetPeerID)
			} else {
				sourcePeers, peerInSources = calc.getAllPeersFromGroups(ctx, rule.Sources, targetPeerID, policy.SourcePostureChecks)
			}

			if rule.DestinationResource.Type == ResourceTypePeer && rule.DestinationResource.ID != "" {
				destinationPeers, peerInDestinations = calc.getPeerFromResource(rule.DestinationResource, targetPeerID)
			} else {
				destinationPeers, peerInDestinations = calc.getAllPeersFromGroups(ctx, rule.Destinations, targetPeerID, nil)
			}

			if rule.Bidirectional {
				if peerInSources {
					generateResources(rule, destinationPeers, FirewallRuleDirectionIN)
				}
				if peerInDestinations {
					generateResources(rule, sourcePeers, FirewallRuleDirectionOUT)
				}
			}

			if peerInSources {
				generateResources(rule, destinationPeers, FirewallRuleDirectionOUT)
			}

			if peerInDestinations {
				generateResources(rule, sourcePeers, FirewallRuleDirectionIN)
			}

			if peerInDestinations && rule.Protocol == PolicyRuleProtocolNetbirdSSH {
				sshEnabled = true
				switch {
				case len(rule.AuthorizedGroups) > 0:
					for groupID, localUsers := range rule.AuthorizedGroups {
						userIDs, ok := calc.components.GroupIDToUserIDs[groupID]
						if !ok {
							continue
						}

						if len(localUsers) == 0 {
							localUsers = []string{auth.Wildcard}
						}

						for _, localUser := range localUsers {
							if authorizedUsers[localUser] == nil {
								authorizedUsers[localUser] = make(map[string]struct{})
							}
							for _, userID := range userIDs {
								authorizedUsers[localUser][userID] = struct{}{}
							}
						}
					}
				case rule.AuthorizedUser != "":
					if authorizedUsers[auth.Wildcard] == nil {
						authorizedUsers[auth.Wildcard] = make(map[string]struct{})
					}
					authorizedUsers[auth.Wildcard][rule.AuthorizedUser] = struct{}{}
				default:
					authorizedUsers[auth.Wildcard] = calc.getAllowedUserIDs()
				}
			} else if peerInDestinations && policyRuleImpliesLegacySSH(rule) && targetPeer.SSHEnabled {
				sshEnabled = true
				authorizedUsers[auth.Wildcard] = calc.getAllowedUserIDs()
			}
		}
	}

	peers, fwRules := getAccumulatedResources()
	return peers, fwRules, authorizedUsers, sshEnabled
}

func (calc *NetworkMapCalculator) getAllowedUserIDs() map[string]struct{} {
	if calc.components.AllowedUserIDs != nil {
		result := make(map[string]struct{}, len(calc.components.AllowedUserIDs))
		for k, v := range calc.components.AllowedUserIDs {
			result[k] = v
		}
		return result
	}
	return make(map[string]struct{})
}

func (calc *NetworkMapCalculator) connResourcesGenerator(ctx context.Context, targetPeer *nbpeer.Peer) (func(*PolicyRule, []*nbpeer.Peer, int), func() ([]*nbpeer.Peer, []*FirewallRule)) {
	rulesExists := make(map[string]struct{})
	peersExists := make(map[string]struct{})
	rules := make([]*FirewallRule, 0)
	peers := make([]*nbpeer.Peer, 0)

	return func(rule *PolicyRule, groupPeers []*nbpeer.Peer, direction int) {
			for _, peer := range groupPeers {
				if peer == nil {
					continue
				}

				if _, ok := peersExists[peer.ID]; !ok {
					peers = append(peers, peer)
					peersExists[peer.ID] = struct{}{}
				}

				fr := FirewallRule{
					PolicyID:  rule.ID,
					PeerIP:    net.IP(peer.IP).String(),
					Direction: direction,
					Action:    string(rule.Action),
					Protocol:  string(rule.Protocol),
				}

				ruleID := rule.ID + fr.PeerIP + string(rune(direction)) +
					fr.Protocol + fr.Action
				for _, port := range rule.Ports {
					ruleID += port
				}
				if _, ok := rulesExists[ruleID]; ok {
					continue
				}
				rulesExists[ruleID] = struct{}{}

				if len(rule.Ports) == 0 && len(rule.PortRanges) == 0 {
					rules = append(rules, &fr)
					continue
				}

				rules = append(rules, expandPortsAndRanges(fr, &PolicyRule{
					ID:         rule.ID,
					Ports:      rule.Ports,
					PortRanges: rule.PortRanges,
					Protocol:   rule.Protocol,
					Action:     rule.Action,
				}, targetPeer)...)
			}
		}, func() ([]*nbpeer.Peer, []*FirewallRule) {
			return peers, rules
		}
}

func (calc *NetworkMapCalculator) getAllPeersFromGroups(ctx context.Context, groups []string, peerID string, sourcePostureChecksIDs []string) ([]*nbpeer.Peer, bool) {
	peerInGroups := false
	uniquePeerIDs := calc.getUniquePeerIDsFromGroupsIDs(ctx, groups)
	filteredPeers := make([]*nbpeer.Peer, 0, len(uniquePeerIDs))

	for _, p := range uniquePeerIDs {
		peerInfo := calc.components.GetPeerInfo(p)
		if peerInfo == nil {
			continue
		}

		if _, ok := calc.components.Peers[p]; !ok {
			continue
		}

		if !calc.components.ValidatePostureChecksOnPeer(p, sourcePostureChecksIDs) {
			continue
		}

		if p == peerID {
			peerInGroups = true
			continue
		}

		filteredPeers = append(filteredPeers, peerInfo)
	}

	return filteredPeers, peerInGroups
}

func (calc *NetworkMapCalculator) getUniquePeerIDsFromGroupsIDs(ctx context.Context, groups []string) []string {
	peerIDs := make(map[string]struct{}, len(groups))
	for _, groupID := range groups {
		group := calc.components.GetGroupInfo(groupID)
		if group == nil {
			continue
		}

		if group.IsGroupAll() || len(groups) == 1 {
			return group.Peers
		}

		for _, peerID := range group.Peers {
			peerIDs[peerID] = struct{}{}
		}
	}

	ids := make([]string, 0, len(peerIDs))
	for peerID := range peerIDs {
		ids = append(ids, peerID)
	}

	return ids
}

func (calc *NetworkMapCalculator) getPeerFromResource(resource Resource, peerID string) ([]*nbpeer.Peer, bool) {
	if resource.ID == peerID {
		return []*nbpeer.Peer{}, true
	}

	peerInfo := calc.components.GetPeerInfo(resource.ID)
	if peerInfo == nil {
		return []*nbpeer.Peer{}, false
	}

	return []*nbpeer.Peer{peerInfo}, false
}

func (calc *NetworkMapCalculator) filterPeersByLoginExpiration(aclPeers []*nbpeer.Peer) ([]*nbpeer.Peer, []*nbpeer.Peer) {
	var peersToConnect []*nbpeer.Peer
	var expiredPeers []*nbpeer.Peer

	for _, p := range aclPeers {
		expired, _ := p.LoginExpired(calc.components.AccountSettings.PeerLoginExpiration)
		if calc.components.AccountSettings.PeerLoginExpirationEnabled && expired {
			expiredPeers = append(expiredPeers, p)
			continue
		}
		peersToConnect = append(peersToConnect, p)
	}

	return peersToConnect, expiredPeers
}

func (calc *NetworkMapCalculator) getPeerDNSManagementStatus(peerID string) bool {
	peerGroups := calc.components.GetPeerGroups(peerID)
	enabled := true
	for _, groupID := range calc.components.DNSSettings.DisabledManagementGroups {
		if _, found := peerGroups[groupID]; found {
			enabled = false
			break
		}
	}
	return enabled
}

func (calc *NetworkMapCalculator) getPeerNSGroups(peerID string) []*nbdns.NameServerGroup {
	groupList := calc.components.GetPeerGroups(peerID)

	var peerNSGroups []*nbdns.NameServerGroup

	for _, nsGroup := range calc.components.NameServerGroups {
		if !nsGroup.Enabled {
			continue
		}
		for _, gID := range nsGroup.Groups {
			_, found := groupList[gID]
			if found {
				targetPeerInfo := calc.components.GetPeerInfo(peerID)
				if targetPeerInfo != nil && !calc.peerIsNameserver(targetPeerInfo, nsGroup) {
					peerNSGroups = append(peerNSGroups, nsGroup.Copy())
					break
				}
			}
		}
	}

	return peerNSGroups
}

func (calc *NetworkMapCalculator) peerIsNameserver(peerInfo *nbpeer.Peer, nsGroup *nbdns.NameServerGroup) bool {
	for _, ns := range nsGroup.NameServers {
		if peerInfo.IP.String() == ns.IP.String() {
			return true
		}
	}
	return false
}

func (calc *NetworkMapCalculator) getRoutesToSync(ctx context.Context, peerID string, aclPeers []*nbpeer.Peer, peerGroups LookupMap) []*route.Route {
	routes, peerDisabledRoutes := calc.getRoutingPeerRoutes(ctx, peerID)
	peerRoutesMembership := make(LookupMap)
	for _, r := range append(routes, peerDisabledRoutes...) {
		peerRoutesMembership[string(r.GetHAUniqueID())] = struct{}{}
	}

	for _, peer := range aclPeers {
		activeRoutes, _ := calc.getRoutingPeerRoutes(ctx, peer.ID)
		groupFilteredRoutes := calc.filterRoutesByGroups(activeRoutes, peerGroups)
		filteredRoutes := calc.filterRoutesFromPeersOfSameHAGroup(groupFilteredRoutes, peerRoutesMembership)
		routes = append(routes, filteredRoutes...)
	}

	return routes
}

func (calc *NetworkMapCalculator) getRoutingPeerRoutes(ctx context.Context, peerID string) (enabledRoutes []*route.Route, disabledRoutes []*route.Route) {
	peerInfo := calc.components.GetPeerInfo(peerID)
	if peerInfo == nil {
		return enabledRoutes, disabledRoutes
	}

	seenRoute := make(map[route.ID]struct{})

	takeRoute := func(r *route.Route, id string) {
		if _, ok := seenRoute[r.ID]; ok {
			return
		}
		seenRoute[r.ID] = struct{}{}

		routeObj := calc.copyRoute(r)
		routeObj.Peer = peerInfo.Key

		if r.Enabled {
			enabledRoutes = append(enabledRoutes, routeObj)
			return
		}
		disabledRoutes = append(disabledRoutes, routeObj)
	}

	for _, r := range calc.components.Routes {
		for _, groupID := range r.PeerGroups {
			group := calc.components.GetGroupInfo(groupID)
			if group == nil {
				continue
			}
			for _, id := range group.Peers {
				if id != peerID {
					continue
				}

				newPeerRoute := calc.copyRoute(r)
				newPeerRoute.Peer = id
				newPeerRoute.PeerGroups = nil
				newPeerRoute.ID = route.ID(string(r.ID) + ":" + id)
				takeRoute(newPeerRoute, id)
				break
			}
		}
		if r.Peer == peerID {
			takeRoute(calc.copyRoute(r), peerID)
		}
	}

	return enabledRoutes, disabledRoutes
}

func (calc *NetworkMapCalculator) copyRoute(r *route.Route) *route.Route {
	var groups, accessControlGroups, peerGroups []string
	var domains domain.List

	if r.Groups != nil {
		groups = append([]string{}, r.Groups...)
	}
	if r.AccessControlGroups != nil {
		accessControlGroups = append([]string{}, r.AccessControlGroups...)
	}
	if r.PeerGroups != nil {
		peerGroups = append([]string{}, r.PeerGroups...)
	}
	if r.Domains != nil {
		domains = append(domain.List{}, r.Domains...)
	}

	return &route.Route{
		ID:                  r.ID,
		AccountID:           r.AccountID,
		Network:             r.Network,
		NetworkType:         r.NetworkType,
		Description:         r.Description,
		Peer:                r.Peer,
		PeerID:              r.PeerID,
		Metric:              r.Metric,
		Masquerade:          r.Masquerade,
		NetID:               r.NetID,
		Enabled:             r.Enabled,
		Groups:              groups,
		AccessControlGroups: accessControlGroups,
		PeerGroups:          peerGroups,
		Domains:             domains,
		KeepRoute:           r.KeepRoute,
		SkipAutoApply:       r.SkipAutoApply,
	}
}

func (calc *NetworkMapCalculator) filterRoutesByGroups(routes []*route.Route, groupListMap LookupMap) []*route.Route {
	var filteredRoutes []*route.Route
	for _, r := range routes {
		for _, groupID := range r.Groups {
			_, found := groupListMap[groupID]
			if found {
				filteredRoutes = append(filteredRoutes, r)
				break
			}
		}
	}
	return filteredRoutes
}

func (calc *NetworkMapCalculator) filterRoutesFromPeersOfSameHAGroup(routes []*route.Route, peerMemberships LookupMap) []*route.Route {
	var filteredRoutes []*route.Route
	for _, r := range routes {
		_, found := peerMemberships[string(r.GetHAUniqueID())]
		if !found {
			filteredRoutes = append(filteredRoutes, r)
		}
	}
	return filteredRoutes
}

func (calc *NetworkMapCalculator) getPeerRoutesFirewallRules(ctx context.Context, peerID string) []*RouteFirewallRule {
	routesFirewallRules := make([]*RouteFirewallRule, 0)

	enabledRoutes, _ := calc.getRoutingPeerRoutes(ctx, peerID)
	for _, r := range enabledRoutes {
		if len(r.AccessControlGroups) == 0 {
			defaultPermit := calc.getDefaultPermit(r)
			routesFirewallRules = append(routesFirewallRules, defaultPermit...)
			continue
		}

		distributionPeers := calc.getDistributionGroupsPeers(r)

		for _, accessGroup := range r.AccessControlGroups {
			policies := calc.getAllRoutePoliciesFromGroups([]string{accessGroup})
			rules := calc.getRouteFirewallRules(ctx, peerID, policies, r, distributionPeers)
			routesFirewallRules = append(routesFirewallRules, rules...)
		}
	}

	return routesFirewallRules
}

func (calc *NetworkMapCalculator) findRoute(routeID route.ID) *route.Route {
	for _, r := range calc.components.Routes {
		if r.ID == routeID {
			return r
		}
	}

	parts := strings.Split(string(routeID), ":")
	if len(parts) > 1 {
		baseRouteID := route.ID(parts[0])
		for _, r := range calc.components.Routes {
			if r.ID == baseRouteID {
				return r
			}
		}
	}

	return nil
}

func (calc *NetworkMapCalculator) getDefaultPermit(r *route.Route) []*RouteFirewallRule {
	var rules []*RouteFirewallRule

	sources := []string{"0.0.0.0/0"}
	if r.Network.Addr().Is6() {
		sources = []string{"::/0"}
	}

	rule := RouteFirewallRule{
		SourceRanges: sources,
		Action:       string(PolicyTrafficActionAccept),
		Destination:  r.Network.String(),
		Protocol:     string(PolicyRuleProtocolALL),
		Domains:      r.Domains,
		IsDynamic:    r.IsDynamic(),
		RouteID:      r.ID,
	}

	rules = append(rules, &rule)

	if r.IsDynamic() {
		ruleV6 := rule
		ruleV6.SourceRanges = []string{"::/0"}
		rules = append(rules, &ruleV6)
	}

	return rules
}

func (calc *NetworkMapCalculator) getDistributionGroupsPeers(r *route.Route) map[string]struct{} {
	distPeers := make(map[string]struct{})
	for _, id := range r.Groups {
		group := calc.components.GetGroupInfo(id)
		if group == nil {
			continue
		}

		for _, pID := range group.Peers {
			distPeers[pID] = struct{}{}
		}
	}
	return distPeers
}

func (calc *NetworkMapCalculator) getAllRoutePoliciesFromGroups(accessControlGroups []string) []*Policy {
	routePolicies := make([]*Policy, 0)
	for _, groupID := range accessControlGroups {
		for _, policy := range calc.components.Policies {
			for _, rule := range policy.Rules {
				for _, destGroupID := range rule.Destinations {
					if destGroupID == groupID {
						routePolicies = append(routePolicies, policy)
						break
					}
				}
			}
		}
	}

	return routePolicies
}

func (calc *NetworkMapCalculator) getRouteFirewallRules(ctx context.Context, peerID string, policies []*Policy, route *route.Route, distributionPeers map[string]struct{}) []*RouteFirewallRule {
	var fwRules []*RouteFirewallRule
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}

		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			rulePeers := calc.getRulePeers(rule, policy.SourcePostureChecks, peerID, distributionPeers)
			rules := generateRouteFirewallRules(ctx, route, rule, rulePeers, FirewallRuleDirectionIN)
			fwRules = append(fwRules, rules...)
		}
	}
	return fwRules
}

func (calc *NetworkMapCalculator) getRulePeers(rule *PolicyRule, postureChecks []string, peerID string, distributionPeers map[string]struct{}) []*nbpeer.Peer {
	distPeersWithPolicy := make(map[string]struct{})
	for _, id := range rule.Sources {
		group := calc.components.GetGroupInfo(id)
		if group == nil {
			continue
		}

		for _, pID := range group.Peers {
			if pID == peerID {
				continue
			}
			_, distPeer := distributionPeers[pID]
			_, valid := calc.components.Peers[pID]
			if distPeer && valid && calc.components.ValidatePostureChecksOnPeer(pID, postureChecks) {
				distPeersWithPolicy[pID] = struct{}{}
			}
		}
	}
	if rule.SourceResource.Type == ResourceTypePeer && rule.SourceResource.ID != "" {
		_, distPeer := distributionPeers[rule.SourceResource.ID]
		_, valid := calc.components.Peers[rule.SourceResource.ID]
		if distPeer && valid && calc.components.ValidatePostureChecksOnPeer(rule.SourceResource.ID, postureChecks) {
			distPeersWithPolicy[rule.SourceResource.ID] = struct{}{}
		}
	}

	distributionGroupPeers := make([]*nbpeer.Peer, 0, len(distPeersWithPolicy))
	for pID := range distPeersWithPolicy {
		peerInfo := calc.components.GetPeerInfo(pID)
		if peerInfo == nil {
			continue
		}
		distributionGroupPeers = append(distributionGroupPeers, peerInfo)
	}
	return distributionGroupPeers
}

func (calc *NetworkMapCalculator) getNetworkResourcesRoutesToSync(ctx context.Context, peerID string) (bool, []*route.Route, map[string]struct{}) {
	var isRoutingPeer bool
	var routes []*route.Route
	allSourcePeers := make(map[string]struct{})

	for _, resource := range calc.components.NetworkResources {
		if !resource.Enabled {
			continue
		}

		var addSourcePeers bool

		networkRoutingPeers, exists := calc.components.RoutersMap[resource.NetworkID]
		if exists {
			if router, ok := networkRoutingPeers[peerID]; ok {
				isRoutingPeer, addSourcePeers = true, true
				routes = append(routes, calc.getNetworkResourcesRoutes(resource, peerID, router)...)
			}
		}

		addedResourceRoute := false
		for _, policy := range calc.components.ResourcePoliciesMap[resource.ID] {
			var peers []string
			if policy.Rules[0].SourceResource.Type == ResourceTypePeer && policy.Rules[0].SourceResource.ID != "" {
				peers = []string{policy.Rules[0].SourceResource.ID}
			} else {
				peers = calc.getUniquePeerIDsFromGroupsIDs(ctx, policy.SourceGroups())
			}
			if addSourcePeers {
				for _, pID := range calc.getPostureValidPeers(peers, policy.SourcePostureChecks) {
					allSourcePeers[pID] = struct{}{}
				}
			} else if calc.peerInSlice(peerID, peers) && calc.components.ValidatePostureChecksOnPeer(peerID, policy.SourcePostureChecks) {
				for peerId, router := range networkRoutingPeers {
					routes = append(routes, calc.getNetworkResourcesRoutes(resource, peerId, router)...)
				}
				addedResourceRoute = true
			}
			if addedResourceRoute {
				break
			}
		}
	}

	return isRoutingPeer, routes, allSourcePeers
}

func (calc *NetworkMapCalculator) getNetworkResourcesRoutes(resource *resourceTypes.NetworkResource, peerID string, router *routerTypes.NetworkRouter) []*route.Route {
	resourceAppliedPolicies := calc.components.ResourcePoliciesMap[resource.ID]

	var routes []*route.Route
	if len(resourceAppliedPolicies) > 0 {
		peerInfo := calc.components.GetPeerInfo(peerID)
		if peerInfo != nil {
			routes = append(routes, calc.networkResourceToRoute(resource, peerInfo, router))
		}
	}

	return routes
}

func (calc *NetworkMapCalculator) networkResourceToRoute(resource *resourceTypes.NetworkResource, peer *nbpeer.Peer, router *routerTypes.NetworkRouter) *route.Route {
	r := &route.Route{
		ID:          route.ID(resource.ID + ":" + peer.ID),
		AccountID:   resource.AccountID,
		Peer:        peer.Key,
		PeerID:      peer.ID,
		Metric:      router.Metric,
		Masquerade:  router.Masquerade,
		Enabled:     resource.Enabled,
		KeepRoute:   true,
		NetID:       route.NetID(resource.Name),
		Description: resource.Description,
	}

	if resource.Type == resourceTypes.Host || resource.Type == resourceTypes.Subnet {
		r.Network = resource.Prefix

		r.NetworkType = route.IPv4Network
		if resource.Prefix.Addr().Is6() {
			r.NetworkType = route.IPv6Network
		}
	}

	if resource.Type == resourceTypes.Domain {
		domainList, err := domain.FromStringList([]string{resource.Domain})
		if err == nil {
			r.Domains = domainList
			r.NetworkType = route.DomainNetwork
			r.Network = netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 0, 2, 0}), 32)
		}
	}

	return r
}

func (calc *NetworkMapCalculator) getPostureValidPeers(inputPeers []string, postureChecksIDs []string) []string {
	var dest []string
	for _, peerID := range inputPeers {
		if calc.components.ValidatePostureChecksOnPeer(peerID, postureChecksIDs) {
			dest = append(dest, peerID)
		}
	}
	return dest
}

func (calc *NetworkMapCalculator) peerInSlice(peerID string, peers []string) bool {
	for _, p := range peers {
		if p == peerID {
			return true
		}
	}
	return false
}

func (calc *NetworkMapCalculator) getPeerNetworkResourceFirewallRules(ctx context.Context, peerID string, routes []*route.Route) []*RouteFirewallRule {
	routesFirewallRules := make([]*RouteFirewallRule, 0)

	peerInfo := calc.components.GetPeerInfo(peerID)
	if peerInfo == nil {
		return routesFirewallRules
	}

	for _, r := range routes {
		if r.Peer != peerInfo.Key {
			continue
		}

		resourceID := string(r.GetResourceID())
		resourcePolicies := calc.components.ResourcePoliciesMap[resourceID]
		distributionPeers := calc.getPoliciesSourcePeers(resourcePolicies)

		rules := calc.getRouteFirewallRules(ctx, peerID, resourcePolicies, r, distributionPeers)
		for _, rule := range rules {
			if len(rule.SourceRanges) > 0 {
				routesFirewallRules = append(routesFirewallRules, rule)
			}
		}
	}

	return routesFirewallRules
}

func (calc *NetworkMapCalculator) getPoliciesSourcePeers(policies []*Policy) map[string]struct{} {
	sourcePeers := make(map[string]struct{})

	for _, policy := range policies {
		for _, rule := range policy.Rules {
			for _, sourceGroup := range rule.Sources {
				group := calc.components.GetGroupInfo(sourceGroup)
				if group == nil {
					continue
				}

				for _, peer := range group.Peers {
					sourcePeers[peer] = struct{}{}
				}
			}

			if rule.SourceResource.Type == ResourceTypePeer && rule.SourceResource.ID != "" {
				sourcePeers[rule.SourceResource.ID] = struct{}{}
			}
		}
	}

	return sourcePeers
}

func (calc *NetworkMapCalculator) addNetworksRoutingPeers(
	networkResourcesRoutes []*route.Route,
	peerID string,
	peersToConnect []*nbpeer.Peer,
	expiredPeers []*nbpeer.Peer,
	isRouter bool,
	sourcePeers map[string]struct{},
) []*nbpeer.Peer {

	networkRoutesPeers := make(map[string]struct{}, len(networkResourcesRoutes))
	for _, r := range networkResourcesRoutes {
		networkRoutesPeers[r.PeerID] = struct{}{}
	}

	delete(sourcePeers, peerID)
	delete(networkRoutesPeers, peerID)

	for _, existingPeer := range peersToConnect {
		delete(sourcePeers, existingPeer.ID)
		delete(networkRoutesPeers, existingPeer.ID)
	}
	for _, expPeer := range expiredPeers {
		delete(sourcePeers, expPeer.ID)
		delete(networkRoutesPeers, expPeer.ID)
	}

	missingPeers := make(map[string]struct{}, len(sourcePeers)+len(networkRoutesPeers))
	if isRouter {
		for p := range sourcePeers {
			missingPeers[p] = struct{}{}
		}
	}
	for p := range networkRoutesPeers {
		missingPeers[p] = struct{}{}
	}

	for p := range missingPeers {
		peerInfo := calc.components.GetPeerInfo(p)
		if peerInfo != nil {
			peersToConnect = append(peersToConnect, peerInfo)
		}
	}

	return peersToConnect
}
