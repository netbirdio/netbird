package types

import (
	"context"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
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

const EnvNewNetworkMapCompacted = "NB_NETWORK_MAP_COMPACTED"

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

	RouterPeers map[string]*nbpeer.Peer
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

func (c *NetworkMapComponents) GetRouterPeerInfo(peerID string) *nbpeer.Peer {
	return c.RouterPeers[peerID]
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

func CalculateNetworkMapFromComponents(ctx context.Context, components *NetworkMapComponents) *NetworkMap {
	return components.Calculate(ctx)
}

func (c *NetworkMapComponents) Calculate(ctx context.Context) *NetworkMap {
	targetPeerID := c.PeerID

	peerGroups := c.GetPeerGroups(targetPeerID)

	aclPeers, firewallRules, authorizedUsers, sshEnabled := c.getPeerConnectionResources(targetPeerID)

	peersToConnect, expiredPeers := c.filterPeersByLoginExpiration(aclPeers)

	routesUpdate := c.getRoutesToSync(targetPeerID, peersToConnect, peerGroups)
	routesFirewallRules := c.getPeerRoutesFirewallRules(ctx, targetPeerID)

	isRouter, networkResourcesRoutes, sourcePeers := c.getNetworkResourcesRoutesToSync(targetPeerID)
	var networkResourcesFirewallRules []*RouteFirewallRule
	if isRouter {
		networkResourcesFirewallRules = c.getPeerNetworkResourceFirewallRules(ctx, targetPeerID, networkResourcesRoutes)
	}

	peersToConnectIncludingRouters := c.addNetworksRoutingPeers(
		networkResourcesRoutes,
		targetPeerID,
		peersToConnect,
		expiredPeers,
		isRouter,
		sourcePeers,
	)

	dnsManagementStatus := c.getPeerDNSManagementStatus(targetPeerID)
	dnsUpdate := nbdns.Config{
		ServiceEnable: dnsManagementStatus,
	}

	if dnsManagementStatus {
		var customZones []nbdns.CustomZone

		if c.CustomZoneDomain != "" && len(c.AllDNSRecords) > 0 {
			customZones = append(customZones, nbdns.CustomZone{
				Domain:  c.CustomZoneDomain,
				Records: c.AllDNSRecords,
			})
		}

		customZones = append(customZones, c.AccountZones...)

		dnsUpdate.CustomZones = customZones
		dnsUpdate.NameServerGroups = c.getPeerNSGroups(targetPeerID)
	}

	return &NetworkMap{
		Peers:               peersToConnectIncludingRouters,
		Network:             c.Network.Copy(),
		Routes:              append(networkResourcesRoutes, routesUpdate...),
		DNSConfig:           dnsUpdate,
		OfflinePeers:        expiredPeers,
		FirewallRules:       firewallRules,
		RoutesFirewallRules: append(networkResourcesFirewallRules, routesFirewallRules...),
		AuthorizedUsers:     authorizedUsers,
		EnableSSH:           sshEnabled,
	}
}

func (c *NetworkMapComponents) getPeerConnectionResources(targetPeerID string) ([]*nbpeer.Peer, []*FirewallRule, map[string]map[string]struct{}, bool) {
	targetPeer := c.GetPeerInfo(targetPeerID)
	if targetPeer == nil {
		return nil, nil, nil, false
	}

	generateResources, getAccumulatedResources := c.connResourcesGenerator(targetPeer)
	authorizedUsers := make(map[string]map[string]struct{})
	sshEnabled := false

	for _, policy := range c.Policies {
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
				sourcePeers, peerInSources = c.getPeerFromResource(rule.SourceResource, targetPeerID)
			} else {
				sourcePeers, peerInSources = c.getAllPeersFromGroups(rule.Sources, targetPeerID, policy.SourcePostureChecks)
			}

			if rule.DestinationResource.Type == ResourceTypePeer && rule.DestinationResource.ID != "" {
				destinationPeers, peerInDestinations = c.getPeerFromResource(rule.DestinationResource, targetPeerID)
			} else {
				destinationPeers, peerInDestinations = c.getAllPeersFromGroups(rule.Destinations, targetPeerID, nil)
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
						userIDs, ok := c.GroupIDToUserIDs[groupID]
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
					authorizedUsers[auth.Wildcard] = c.getAllowedUserIDs()
				}
			} else if peerInDestinations && policyRuleImpliesLegacySSH(rule) && targetPeer.SSHEnabled {
				sshEnabled = true
				authorizedUsers[auth.Wildcard] = c.getAllowedUserIDs()
			}
		}
	}

	peers, fwRules := getAccumulatedResources()
	return peers, fwRules, authorizedUsers, sshEnabled
}

func (c *NetworkMapComponents) getAllowedUserIDs() map[string]struct{} {
	if c.AllowedUserIDs != nil {
		result := make(map[string]struct{}, len(c.AllowedUserIDs))
		maps.Copy(result, c.AllowedUserIDs)
		return result
	}
	return make(map[string]struct{})
}

func (c *NetworkMapComponents) connResourcesGenerator(targetPeer *nbpeer.Peer) (func(*PolicyRule, []*nbpeer.Peer, int), func() ([]*nbpeer.Peer, []*FirewallRule)) {
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

				protocol := rule.Protocol
				if protocol == PolicyRuleProtocolNetbirdSSH {
					protocol = PolicyRuleProtocolTCP
				}

				fr := FirewallRule{
					PolicyID:  rule.ID,
					PeerIP:    net.IP(peer.IP).String(),
					Direction: direction,
					Action:    string(rule.Action),
					Protocol:  string(protocol),
				}

				ruleID := rule.ID + fr.PeerIP + strconv.Itoa(direction) +
					fr.Protocol + fr.Action + strings.Join(rule.Ports, ",")
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

func (c *NetworkMapComponents) getAllPeersFromGroups(groups []string, peerID string, sourcePostureChecksIDs []string) ([]*nbpeer.Peer, bool) {
	peerInGroups := false
	uniquePeerIDs := c.getUniquePeerIDsFromGroupsIDs(groups)
	filteredPeers := make([]*nbpeer.Peer, 0, len(uniquePeerIDs))

	for _, p := range uniquePeerIDs {
		peerInfo := c.GetPeerInfo(p)
		if peerInfo == nil {
			continue
		}

		if _, ok := c.Peers[p]; !ok {
			continue
		}

		if !c.ValidatePostureChecksOnPeer(p, sourcePostureChecksIDs) {
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

func (c *NetworkMapComponents) getUniquePeerIDsFromGroupsIDs(groups []string) []string {
	peerIDs := make(map[string]struct{}, len(groups))
	for _, groupID := range groups {
		group := c.GetGroupInfo(groupID)
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

func (c *NetworkMapComponents) getPeerFromResource(resource Resource, peerID string) ([]*nbpeer.Peer, bool) {
	if resource.ID == peerID {
		return []*nbpeer.Peer{}, true
	}

	peerInfo := c.GetPeerInfo(resource.ID)
	if peerInfo == nil {
		return []*nbpeer.Peer{}, false
	}

	return []*nbpeer.Peer{peerInfo}, false
}

func (c *NetworkMapComponents) filterPeersByLoginExpiration(aclPeers []*nbpeer.Peer) ([]*nbpeer.Peer, []*nbpeer.Peer) {
	var peersToConnect []*nbpeer.Peer
	var expiredPeers []*nbpeer.Peer

	for _, p := range aclPeers {
		expired, _ := p.LoginExpired(c.AccountSettings.PeerLoginExpiration)
		if c.AccountSettings.PeerLoginExpirationEnabled && expired {
			expiredPeers = append(expiredPeers, p)
			continue
		}
		peersToConnect = append(peersToConnect, p)
	}

	return peersToConnect, expiredPeers
}

func (c *NetworkMapComponents) getPeerDNSManagementStatus(peerID string) bool {
	peerGroups := c.GetPeerGroups(peerID)
	enabled := true
	for _, groupID := range c.DNSSettings.DisabledManagementGroups {
		if _, found := peerGroups[groupID]; found {
			enabled = false
			break
		}
	}
	return enabled
}

func (c *NetworkMapComponents) getPeerNSGroups(peerID string) []*nbdns.NameServerGroup {
	groupList := c.GetPeerGroups(peerID)

	var peerNSGroups []*nbdns.NameServerGroup

	for _, nsGroup := range c.NameServerGroups {
		if !nsGroup.Enabled {
			continue
		}
		for _, gID := range nsGroup.Groups {
			_, found := groupList[gID]
			if found {
				targetPeerInfo := c.GetPeerInfo(peerID)
				if targetPeerInfo != nil && !c.peerIsNameserver(targetPeerInfo, nsGroup) {
					peerNSGroups = append(peerNSGroups, nsGroup.Copy())
					break
				}
			}
		}
	}

	return peerNSGroups
}

func (c *NetworkMapComponents) peerIsNameserver(peerInfo *nbpeer.Peer, nsGroup *nbdns.NameServerGroup) bool {
	for _, ns := range nsGroup.NameServers {
		if peerInfo.IP.String() == ns.IP.String() {
			return true
		}
	}
	return false
}

func (c *NetworkMapComponents) getRoutesToSync(peerID string, aclPeers []*nbpeer.Peer, peerGroups LookupMap) []*route.Route {
	routes, peerDisabledRoutes := c.getRoutingPeerRoutes(peerID)
	peerRoutesMembership := make(LookupMap)
	for _, r := range append(routes, peerDisabledRoutes...) {
		peerRoutesMembership[string(r.GetHAUniqueID())] = struct{}{}
	}

	for _, peer := range aclPeers {
		activeRoutes, _ := c.getRoutingPeerRoutes(peer.ID)
		groupFilteredRoutes := c.filterRoutesByGroups(activeRoutes, peerGroups)
		filteredRoutes := c.filterRoutesFromPeersOfSameHAGroup(groupFilteredRoutes, peerRoutesMembership)
		routes = append(routes, filteredRoutes...)
	}

	return routes
}

func (c *NetworkMapComponents) getRoutingPeerRoutes(peerID string) (enabledRoutes []*route.Route, disabledRoutes []*route.Route) {
	peerInfo := c.GetPeerInfo(peerID)
	if peerInfo == nil {
		peerInfo = c.GetRouterPeerInfo(peerID)
	}
	if peerInfo == nil {
		return enabledRoutes, disabledRoutes
	}

	seenRoute := make(map[route.ID]struct{})

	takeRoute := func(r *route.Route) {
		if _, ok := seenRoute[r.ID]; ok {
			return
		}
		seenRoute[r.ID] = struct{}{}

		routeObj := c.copyRoute(r)
		routeObj.Peer = peerInfo.Key

		if r.Enabled {
			enabledRoutes = append(enabledRoutes, routeObj)
			return
		}
		disabledRoutes = append(disabledRoutes, routeObj)
	}

	for _, r := range c.Routes {
		for _, groupID := range r.PeerGroups {
			group := c.GetGroupInfo(groupID)
			if group == nil {
				continue
			}
			for _, id := range group.Peers {
				if id != peerID {
					continue
				}

				newPeerRoute := c.copyRoute(r)
				newPeerRoute.Peer = id
				newPeerRoute.PeerGroups = nil
				newPeerRoute.ID = route.ID(string(r.ID) + ":" + id)
				takeRoute(newPeerRoute)
				break
			}
		}
		if r.Peer == peerID {
			takeRoute(c.copyRoute(r))
		}
	}

	return enabledRoutes, disabledRoutes
}

func (c *NetworkMapComponents) copyRoute(r *route.Route) *route.Route {
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

func (c *NetworkMapComponents) filterRoutesByGroups(routes []*route.Route, groupListMap LookupMap) []*route.Route {
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

func (c *NetworkMapComponents) filterRoutesFromPeersOfSameHAGroup(routes []*route.Route, peerMemberships LookupMap) []*route.Route {
	var filteredRoutes []*route.Route
	for _, r := range routes {
		_, found := peerMemberships[string(r.GetHAUniqueID())]
		if !found {
			filteredRoutes = append(filteredRoutes, r)
		}
	}
	return filteredRoutes
}

func (c *NetworkMapComponents) getPeerRoutesFirewallRules(ctx context.Context, peerID string) []*RouteFirewallRule {
	routesFirewallRules := make([]*RouteFirewallRule, 0)

	enabledRoutes, _ := c.getRoutingPeerRoutes(peerID)
	for _, r := range enabledRoutes {
		if len(r.AccessControlGroups) == 0 {
			defaultPermit := c.getDefaultPermit(r)
			routesFirewallRules = append(routesFirewallRules, defaultPermit...)
			continue
		}

		distributionPeers := c.getDistributionGroupsPeers(r)

		for _, accessGroup := range r.AccessControlGroups {
			policies := c.getAllRoutePoliciesFromGroups([]string{accessGroup})
			rules := c.getRouteFirewallRules(ctx, peerID, policies, r, distributionPeers)
			routesFirewallRules = append(routesFirewallRules, rules...)
		}
	}

	return routesFirewallRules
}

func (c *NetworkMapComponents) getDefaultPermit(r *route.Route) []*RouteFirewallRule {
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

func (c *NetworkMapComponents) getDistributionGroupsPeers(r *route.Route) map[string]struct{} {
	distPeers := make(map[string]struct{})
	for _, id := range r.Groups {
		group := c.GetGroupInfo(id)
		if group == nil {
			continue
		}

		for _, pID := range group.Peers {
			distPeers[pID] = struct{}{}
		}
	}
	return distPeers
}

func (c *NetworkMapComponents) getAllRoutePoliciesFromGroups(accessControlGroups []string) []*Policy {
	routePolicies := make([]*Policy, 0)
	for _, groupID := range accessControlGroups {
		for _, policy := range c.Policies {
			for _, rule := range policy.Rules {
				if slices.Contains(rule.Destinations, groupID) {
					routePolicies = append(routePolicies, policy)
				}
			}
		}
	}

	return routePolicies
}

func (c *NetworkMapComponents) getRouteFirewallRules(ctx context.Context, peerID string, policies []*Policy, route *route.Route, distributionPeers map[string]struct{}) []*RouteFirewallRule {
	var fwRules []*RouteFirewallRule
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}

		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			rulePeers := c.getRulePeers(rule, policy.SourcePostureChecks, peerID, distributionPeers)
			rules := generateRouteFirewallRules(ctx, route, rule, rulePeers, FirewallRuleDirectionIN)
			fwRules = append(fwRules, rules...)
		}
	}
	return fwRules
}

func (c *NetworkMapComponents) getRulePeers(rule *PolicyRule, postureChecks []string, peerID string, distributionPeers map[string]struct{}) []*nbpeer.Peer {
	distPeersWithPolicy := make(map[string]struct{})
	for _, id := range rule.Sources {
		group := c.GetGroupInfo(id)
		if group == nil {
			continue
		}

		for _, pID := range group.Peers {
			if pID == peerID {
				continue
			}
			_, distPeer := distributionPeers[pID]
			_, valid := c.Peers[pID]
			if distPeer && valid && c.ValidatePostureChecksOnPeer(pID, postureChecks) {
				distPeersWithPolicy[pID] = struct{}{}
			}
		}
	}
	if rule.SourceResource.Type == ResourceTypePeer && rule.SourceResource.ID != "" {
		_, distPeer := distributionPeers[rule.SourceResource.ID]
		_, valid := c.Peers[rule.SourceResource.ID]
		if distPeer && valid && c.ValidatePostureChecksOnPeer(rule.SourceResource.ID, postureChecks) {
			distPeersWithPolicy[rule.SourceResource.ID] = struct{}{}
		}
	}

	distributionGroupPeers := make([]*nbpeer.Peer, 0, len(distPeersWithPolicy))
	for pID := range distPeersWithPolicy {
		peerInfo := c.GetPeerInfo(pID)
		if peerInfo == nil {
			continue
		}
		distributionGroupPeers = append(distributionGroupPeers, peerInfo)
	}
	return distributionGroupPeers
}

func (c *NetworkMapComponents) getNetworkResourcesRoutesToSync(peerID string) (bool, []*route.Route, map[string]struct{}) {
	var isRoutingPeer bool
	var routes []*route.Route
	allSourcePeers := make(map[string]struct{})

	for _, resource := range c.NetworkResources {
		if !resource.Enabled {
			continue
		}

		var addSourcePeers bool

		networkRoutingPeers, exists := c.RoutersMap[resource.NetworkID]
		if exists {
			if router, ok := networkRoutingPeers[peerID]; ok {
				isRoutingPeer, addSourcePeers = true, true
				routes = append(routes, c.getNetworkResourcesRoutes(resource, peerID, router)...)
			}
		}

		addedResourceRoute := false
		for _, policy := range c.ResourcePoliciesMap[resource.ID] {
			var peers []string
			if policy.Rules[0].SourceResource.Type == ResourceTypePeer && policy.Rules[0].SourceResource.ID != "" {
				peers = []string{policy.Rules[0].SourceResource.ID}
			} else {
				peers = c.getUniquePeerIDsFromGroupsIDs(policy.SourceGroups())
			}
			if addSourcePeers {
				for _, pID := range c.getPostureValidPeers(peers, policy.SourcePostureChecks) {
					allSourcePeers[pID] = struct{}{}
				}
			} else if slices.Contains(peers, peerID) && c.ValidatePostureChecksOnPeer(peerID, policy.SourcePostureChecks) {
				for peerId, router := range networkRoutingPeers {
					routes = append(routes, c.getNetworkResourcesRoutes(resource, peerId, router)...)
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

func (c *NetworkMapComponents) getNetworkResourcesRoutes(resource *resourceTypes.NetworkResource, peerID string, router *routerTypes.NetworkRouter) []*route.Route {
	resourceAppliedPolicies := c.ResourcePoliciesMap[resource.ID]

	var routes []*route.Route
	if len(resourceAppliedPolicies) > 0 {
		peerInfo := c.GetPeerInfo(peerID)
		if peerInfo != nil {
			routes = append(routes, c.networkResourceToRoute(resource, peerInfo, router))
		}
	}

	return routes
}

func (c *NetworkMapComponents) networkResourceToRoute(resource *resourceTypes.NetworkResource, peer *nbpeer.Peer, router *routerTypes.NetworkRouter) *route.Route {
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

func (c *NetworkMapComponents) getPostureValidPeers(inputPeers []string, postureChecksIDs []string) []string {
	var dest []string
	for _, peerID := range inputPeers {
		if c.ValidatePostureChecksOnPeer(peerID, postureChecksIDs) {
			dest = append(dest, peerID)
		}
	}
	return dest
}

func (c *NetworkMapComponents) getPeerNetworkResourceFirewallRules(ctx context.Context, peerID string, routes []*route.Route) []*RouteFirewallRule {
	routesFirewallRules := make([]*RouteFirewallRule, 0)

	peerInfo := c.GetPeerInfo(peerID)
	if peerInfo == nil {
		return routesFirewallRules
	}

	for _, r := range routes {
		if r.Peer != peerInfo.Key {
			continue
		}

		resourceID := string(r.GetResourceID())
		resourcePolicies := c.ResourcePoliciesMap[resourceID]
		distributionPeers := c.getPoliciesSourcePeers(resourcePolicies)

		rules := c.getRouteFirewallRules(ctx, peerID, resourcePolicies, r, distributionPeers)
		for _, rule := range rules {
			if len(rule.SourceRanges) > 0 {
				routesFirewallRules = append(routesFirewallRules, rule)
			}
		}
	}

	return routesFirewallRules
}

func (c *NetworkMapComponents) getPoliciesSourcePeers(policies []*Policy) map[string]struct{} {
	sourcePeers := make(map[string]struct{})

	for _, policy := range policies {
		for _, rule := range policy.Rules {
			for _, sourceGroup := range rule.Sources {
				group := c.GetGroupInfo(sourceGroup)
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

func (c *NetworkMapComponents) addNetworksRoutingPeers(
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
		peerInfo := c.GetPeerInfo(p)
		if peerInfo == nil {
			peerInfo = c.GetRouterPeerInfo(p)
		}
		if peerInfo != nil {
			peersToConnect = append(peersToConnect, peerInfo)
		}
	}

	return peersToConnect
}
