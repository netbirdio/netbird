package types

import (
	"context"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
	auth "github.com/netbirdio/netbird/shared/sessionauth"
)

type NetworkMapComponents struct {
	PeerID string

	Network          *Network
	AccountSettings  *AccountSettingsInfo
	DNSSettings      *DNSSettings
	CustomZoneDomain string

	Peers               map[string]*nbpeer.Peer
	Groups              map[string]*Group
	Policies            []*Policy
	Routes              []*route.Route
	NameServerGroups    []*nbdns.NameServerGroup
	AllDNSRecords       []nbdns.SimpleRecord
	AccountZones        []nbdns.CustomZone
	ResourcePoliciesMap map[string][]*Policy
	RoutersMap          map[string]map[string]*routerTypes.NetworkRouter
	NetworkResources    []*resourceTypes.NetworkResource

	GroupIDToUserIDs   map[string][]string
	AllowedUserIDs     map[string]struct{}
	PostureFailedPeers map[string]map[string]struct{}

	RouterPeers map[string]*nbpeer.Peer

	routesByPeerOnce sync.Once
	routesByPeerIdx  map[string][]routeIndexEntry
}

type routeIndexEntry struct {
	route    *route.Route
	viaGroup bool
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

	connRes := c.getPeerConnectionResources(ctx, targetPeerID)
	aclPeers := connRes.peers

	peersToConnect, expiredPeers := c.filterPeersByLoginExpiration(aclPeers)

	includeIPv6 := false
	if p := c.Peers[targetPeerID]; p != nil {
		includeIPv6 = p.SupportsIPv6() && p.IPv6.IsValid()
	}
	routesUpdate := filterAndExpandRoutes(c.getRoutesToSync(targetPeerID, peersToConnect, peerGroups), includeIPv6)
	routesFirewallRules := c.getPeerRoutesFirewallRules(ctx, targetPeerID, includeIPv6)

	isRouter, networkResourcesRoutes, sourcePeers := c.getNetworkResourcesRoutesToSync(targetPeerID)
	var networkResourcesFirewallRules []*RouteFirewallRule
	if isRouter {
		networkResourcesFirewallRules = c.getPeerNetworkResourceFirewallRules(ctx, targetPeerID, networkResourcesRoutes, includeIPv6)
	}

	peersToConnectIncludingRouters := c.addNetworksRoutingPeers(
		networkResourcesRoutes,
		targetPeerID,
		peersToConnect,
		expiredPeers,
		isRouter,
		sourcePeers,
	)

	dnsManagementStatus := c.getPeerDNSManagementStatusFromGroups(peerGroups)
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
		dnsUpdate.NameServerGroups = c.getPeerNSGroupsFromGroups(targetPeerID, peerGroups)
	}

	return &NetworkMap{
		Peers:               peersToConnectIncludingRouters,
		Network:             c.Network.Copy(),
		Routes:              append(filterAndExpandRoutes(networkResourcesRoutes, includeIPv6), routesUpdate...),
		DNSConfig:           dnsUpdate,
		OfflinePeers:        expiredPeers,
		FirewallRules:       connRes.firewallRules,
		RoutesFirewallRules: append(networkResourcesFirewallRules, routesFirewallRules...),
		AuthorizedUsers:     connRes.authorizedUsers,
		VNCAuthorizedUsers:  connRes.vncAuthorizedUsers,
		VNCSessionPubKeys:   connRes.vncSessionPubKeys,
		EnableSSH:           connRes.sshEnabled,
	}
}

// peerConnectionResult holds the output of getPeerConnectionResources.
type peerConnectionResult struct {
	peers              []*nbpeer.Peer
	firewallRules      []*FirewallRule
	authorizedUsers    map[string]map[string]struct{}
	vncAuthorizedUsers map[string]map[string]struct{}
	vncSessionPubKeys  []VNCSessionPubKey
	sshEnabled         bool
}

func (c *NetworkMapComponents) getPeerConnectionResources(ctx context.Context, targetPeerID string) peerConnectionResult {
	targetPeer := c.GetPeerInfo(targetPeerID)
	if targetPeer == nil {
		return peerConnectionResult{}
	}

	generateResources, getAccumulatedResources := c.connResourcesGenerator(targetPeer)
	state := &peerConnResolveState{
		authorizedUsers:    make(map[string]map[string]struct{}),
		vncAuthorizedUsers: make(map[string]map[string]struct{}),
	}

	for _, policy := range c.Policies {
		if !policy.Enabled {
			continue
		}
		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}
			c.applyPolicyRule(ctx, rule, policy.SourcePostureChecks, targetPeer, targetPeerID, generateResources, state)
		}
	}

	peers, fwRules := getAccumulatedResources()
	return peerConnectionResult{
		peers:              peers,
		firewallRules:      fwRules,
		authorizedUsers:    state.authorizedUsers,
		vncAuthorizedUsers: state.vncAuthorizedUsers,
		vncSessionPubKeys:  state.vncSessionPubKeys,
		sshEnabled:         state.sshEnabled,
	}
}

func (c *NetworkMapComponents) applyPolicyRule(
	ctx context.Context,
	rule *PolicyRule,
	sourcePostureChecks []string,
	targetPeer *nbpeer.Peer,
	targetPeerID string,
	generateResources func(*PolicyRule, []*nbpeer.Peer, int),
	state *peerConnResolveState,
) {
	sourcePeers, peerInSources := c.resolveRuleEndpoint(rule.SourceResource, rule.Sources, targetPeerID, sourcePostureChecks)
	destinationPeers, peerInDestinations := c.resolveRuleEndpoint(rule.DestinationResource, rule.Destinations, targetPeerID, nil)

	cb := ruleAuthCallbacks{
		collectSSHUsers: func(r *PolicyRule, t map[string]map[string]struct{}) {
			c.collectAuthorizedUsers(ctx, r, t)
		},
		collectVNCUsers: func(r *PolicyRule, t map[string]map[string]struct{}) {
			c.collectAuthorizedUsers(ctx, r, t)
		},
		getAllowedUserIDs: c.getAllowedUserIDs,
	}
	applyResolvedRuleToState(rule, sourcePeers, destinationPeers, peerInSources, peerInDestinations, targetPeer.SSHEnabled, generateResources, cb, state)
}

func (c *NetworkMapComponents) resolveRuleEndpoint(
	resource Resource,
	groups []string,
	peerID string,
	postureChecks []string,
) ([]*nbpeer.Peer, bool) {
	if resource.Type == ResourceTypePeer && resource.ID != "" {
		return c.getPeerFromResource(resource, peerID, postureChecks)
	}
	return c.getAllPeersFromGroups(groups, peerID, postureChecks)
}

// collectAuthorizedUsers populates the target map with authorized user mappings from the rule.
func (c *NetworkMapComponents) collectAuthorizedUsers(ctx context.Context, rule *PolicyRule, target map[string]map[string]struct{}) {
	switch {
	case len(rule.AuthorizedGroups) > 0:
		mergeAuthorizedGroupUsers(ctx, rule.AuthorizedGroups, c.GroupIDToUserIDs, target)
	case rule.AuthorizedUser != "":
		ensureWildcardUser(target, rule.AuthorizedUser)
	default:
		target[auth.Wildcard] = c.getAllowedUserIDs()
	}
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
			effectiveRule, protocol := normalizePolicyRuleProtocol(rule)
			rule = effectiveRule

			protocolStr := string(protocol)
			actionStr := string(rule.Action)
			dirStr := strconv.Itoa(direction)
			portsJoined := strings.Join(rule.Ports, ",")

			for _, peer := range groupPeers {
				if peer == nil {
					continue
				}

				if _, ok := peersExists[peer.ID]; !ok {
					peers = append(peers, peer)
					peersExists[peer.ID] = struct{}{}
				}

				peerIP := peer.IP.String()

				fr := FirewallRule{
					PolicyID:  rule.ID,
					PeerIP:    peerIP,
					Direction: direction,
					Action:    actionStr,
					Protocol:  protocolStr,
				}

				ruleID := rule.ID + peerIP + dirStr +
					protocolStr + actionStr + portsJoined
				if _, ok := rulesExists[ruleID]; ok {
					continue
				}
				rulesExists[ruleID] = struct{}{}

				if len(rule.Ports) == 0 && len(rule.PortRanges) == 0 {
					rules = append(rules, &fr)
				} else {
					rules = append(rules, expandPortsAndRanges(fr, rule, targetPeer)...)
				}

				rules = appendIPv6FirewallRule(rules, rulesExists, peer, targetPeer, rule, firewallRuleContext{
					direction:   direction,
					dirStr:      dirStr,
					protocolStr: protocolStr,
					actionStr:   actionStr,
					portsJoined: portsJoined,
				})
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

func (c *NetworkMapComponents) getPeerFromResource(resource Resource, peerID string, postureChecks []string) ([]*nbpeer.Peer, bool) {
	if resource.ID == peerID {
		if len(postureChecks) > 0 && !c.ValidatePostureChecksOnPeer(peerID, postureChecks) {
			return []*nbpeer.Peer{}, false
		}
		return []*nbpeer.Peer{}, true
	}

	peerInfo := c.GetPeerInfo(resource.ID)
	if peerInfo == nil {
		return []*nbpeer.Peer{}, false
	}
	if len(postureChecks) > 0 && !c.ValidatePostureChecksOnPeer(resource.ID, postureChecks) {
		return []*nbpeer.Peer{}, false
	}

	return []*nbpeer.Peer{peerInfo}, false
}

func (c *NetworkMapComponents) filterPeersByLoginExpiration(aclPeers []*nbpeer.Peer) ([]*nbpeer.Peer, []*nbpeer.Peer) {
	peersToConnect := make([]*nbpeer.Peer, 0, len(aclPeers))
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

func (c *NetworkMapComponents) getPeerDNSManagementStatusFromGroups(peerGroups map[string]struct{}) bool {
	for _, groupID := range c.DNSSettings.DisabledManagementGroups {
		if _, found := peerGroups[groupID]; found {
			return false
		}
	}
	return true
}

func (c *NetworkMapComponents) getPeerNSGroupsFromGroups(peerID string, groupList map[string]struct{}) []*nbdns.NameServerGroup {
	var peerNSGroups []*nbdns.NameServerGroup

	targetPeerInfo := c.GetPeerInfo(peerID)
	if targetPeerInfo == nil {
		return peerNSGroups
	}

	peerIPStr := targetPeerInfo.IP.String()

	for _, nsGroup := range c.NameServerGroups {
		if !nsGroup.Enabled {
			continue
		}
		for _, gID := range nsGroup.Groups {
			if _, found := groupList[gID]; found {
				if !c.peerIsNameserver(peerIPStr, nsGroup) {
					peerNSGroups = append(peerNSGroups, nsGroup.Copy())
				}
				break
			}
		}
	}

	return peerNSGroups
}

func (c *NetworkMapComponents) peerIsNameserver(peerIPStr string, nsGroup *nbdns.NameServerGroup) bool {
	for _, ns := range nsGroup.NameServers {
		if peerIPStr == ns.IP.String() {
			return true
		}
	}
	return false
}

// filterAndExpandRoutes drops v6 routes for non-capable peers and duplicates
// the default v4 route (0.0.0.0/0) as ::/0 for v6-capable peers.
// TODO: the "-v6" suffix on IDs could collide with user-supplied route IDs.
func filterAndExpandRoutes(routes []*route.Route, includeIPv6 bool) []*route.Route {
	filtered := make([]*route.Route, 0, len(routes))
	for _, r := range routes {
		if !includeIPv6 && r.Network.Addr().Is6() {
			continue
		}
		filtered = append(filtered, r)

		if includeIPv6 && r.Network.Bits() == 0 && r.Network.Addr().Is4() {
			v6 := r.Copy()
			v6.ID = r.ID + "-v6-default"
			v6.NetID = r.NetID + "-v6"
			v6.Network = netip.MustParsePrefix("::/0")
			v6.NetworkType = route.IPv6Network
			filtered = append(filtered, v6)
		}
	}
	return filtered
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

		r.Peer = peerInfo.Key

		if r.Enabled {
			enabledRoutes = append(enabledRoutes, r)
			return
		}
		disabledRoutes = append(disabledRoutes, r)
	}

	for _, entry := range c.routesByPeer()[peerID] {
		if entry.viaGroup {
			newPeerRoute := entry.route.Copy()
			newPeerRoute.PeerGroups = nil
			newPeerRoute.ID = route.ID(string(entry.route.ID) + ":" + peerID)
			takeRoute(newPeerRoute)
			continue
		}
		takeRoute(entry.route.Copy())
	}

	return enabledRoutes, disabledRoutes
}

func (c *NetworkMapComponents) routesByPeer() map[string][]routeIndexEntry {
	c.routesByPeerOnce.Do(func() {
		idx := make(map[string][]routeIndexEntry)
		for _, r := range c.Routes {
			for _, groupID := range r.PeerGroups {
				group := c.GetGroupInfo(groupID)
				if group == nil {
					continue
				}
				for _, id := range group.Peers {
					idx[id] = append(idx[id], routeIndexEntry{route: r, viaGroup: true})
				}
			}
			if r.Peer != "" {
				idx[r.Peer] = append(idx[r.Peer], routeIndexEntry{route: r})
			}
		}
		c.routesByPeerIdx = idx
	})

	return c.routesByPeerIdx
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

func (c *NetworkMapComponents) getPeerRoutesFirewallRules(ctx context.Context, peerID string, includeIPv6 bool) []*RouteFirewallRule {
	routesFirewallRules := make([]*RouteFirewallRule, 0)

	enabledRoutes, _ := c.getRoutingPeerRoutes(peerID)
	for _, r := range enabledRoutes {
		if len(r.AccessControlGroups) == 0 {
			defaultPermit := c.getDefaultPermit(r, includeIPv6)
			routesFirewallRules = append(routesFirewallRules, defaultPermit...)
			continue
		}

		distributionPeers := c.getDistributionGroupsPeers(r)

		for _, accessGroup := range r.AccessControlGroups {
			policies := c.getAllRoutePoliciesFromGroups([]string{accessGroup})
			rules := c.getRouteFirewallRules(ctx, peerID, policies, r, distributionPeers, includeIPv6)
			routesFirewallRules = append(routesFirewallRules, rules...)
		}
	}

	return routesFirewallRules
}

func (c *NetworkMapComponents) getDefaultPermit(r *route.Route, includeIPv6 bool) []*RouteFirewallRule {
	if r.Network.Addr().Is6() && !includeIPv6 {
		return nil
	}

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

	rules := []*RouteFirewallRule{&rule}

	isDefaultV4 := r.Network.Addr().Is4() && r.Network.Bits() == 0
	if includeIPv6 && (r.IsDynamic() || isDefaultV4) {
		ruleV6 := rule
		ruleV6.SourceRanges = []string{"::/0"}
		if isDefaultV4 {
			ruleV6.Destination = "::/0"
			ruleV6.RouteID = r.ID + "-v6-default"
		}
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

func (c *NetworkMapComponents) getRouteFirewallRules(ctx context.Context, peerID string, policies []*Policy, route *route.Route, distributionPeers map[string]struct{}, includeIPv6 bool) []*RouteFirewallRule {
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
			rules := generateRouteFirewallRules(ctx, route, rule, rulePeers, FirewallRuleDirectionIN, includeIPv6)
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

		newRoutes := c.processResourcePolicies(peerID, resource, networkRoutingPeers, addSourcePeers, allSourcePeers)
		routes = append(routes, newRoutes...)
	}

	return isRoutingPeer, routes, allSourcePeers
}

func (c *NetworkMapComponents) processResourcePolicies(
	peerID string,
	resource *resourceTypes.NetworkResource,
	networkRoutingPeers map[string]*routerTypes.NetworkRouter,
	addSourcePeers bool,
	allSourcePeers map[string]struct{},
) []*route.Route {
	var routes []*route.Route

	for _, policy := range c.ResourcePoliciesMap[resource.ID] {
		peers := c.getResourcePolicyPeers(policy)
		if addSourcePeers {
			for _, pID := range c.getPostureValidPeers(peers, policy.SourcePostureChecks) {
				allSourcePeers[pID] = struct{}{}
			}
			continue
		}

		if slices.Contains(peers, peerID) && c.ValidatePostureChecksOnPeer(peerID, policy.SourcePostureChecks) {
			for peerId, router := range networkRoutingPeers {
				routes = append(routes, c.getNetworkResourcesRoutes(resource, peerId, router)...)
			}
			break
		}
	}

	return routes
}

func (c *NetworkMapComponents) getResourcePolicyPeers(policy *Policy) []string {
	if policy.Rules[0].SourceResource.Type == ResourceTypePeer && policy.Rules[0].SourceResource.ID != "" {
		return []string{policy.Rules[0].SourceResource.ID}
	}
	return c.getUniquePeerIDsFromGroupsIDs(policy.SourceGroups())
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

func (c *NetworkMapComponents) getPeerNetworkResourceFirewallRules(ctx context.Context, peerID string, routes []*route.Route, includeIPv6 bool) []*RouteFirewallRule {
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

		rules := c.getRouteFirewallRules(ctx, peerID, resourcePolicies, r, distributionPeers, includeIPv6)
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

type firewallRuleContext struct {
	direction   int
	dirStr      string
	protocolStr string
	actionStr   string
	portsJoined string
}

func appendIPv6FirewallRule(rules []*FirewallRule, rulesExists map[string]struct{}, peer, targetPeer *nbpeer.Peer, rule *PolicyRule, rc firewallRuleContext) []*FirewallRule {
	if !peer.IPv6.IsValid() || !targetPeer.SupportsIPv6() || !targetPeer.IPv6.IsValid() {
		return rules
	}

	v6IP := peer.IPv6.String()
	v6RuleID := rule.ID + v6IP + rc.dirStr + rc.protocolStr + rc.actionStr + rc.portsJoined
	if _, ok := rulesExists[v6RuleID]; ok {
		return rules
	}
	rulesExists[v6RuleID] = struct{}{}

	v6fr := FirewallRule{
		PolicyID:  rule.ID,
		PeerIP:    v6IP,
		Direction: rc.direction,
		Action:    rc.actionStr,
		Protocol:  rc.protocolStr,
	}
	if len(rule.Ports) == 0 && len(rule.PortRanges) == 0 {
		return append(rules, &v6fr)
	}
	return append(rules, expandPortsAndRanges(v6fr, rule, targetPeer)...)
}
