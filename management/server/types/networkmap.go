package types

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/util"
	"github.com/netbirdio/netbird/route"
)

type NetworkMap struct {
	Peers               []*nbpeer.Peer
	Network             *Network
	Routes              []*route.Route
	DNSConfig           nbdns.Config
	OfflinePeers        []*nbpeer.Peer
	FirewallRules       []*FirewallRule
	RoutesFirewallRules []*RouteFirewallRule
	ForwardingRules     []*ForwardingRule
}

func (nm *NetworkMap) Merge(other *NetworkMap) {
	nm.Peers = mergeUniquePeersByID(nm.Peers, other.Peers)
	nm.Routes = util.MergeUnique(nm.Routes, other.Routes)
	nm.OfflinePeers = mergeUniquePeersByID(nm.OfflinePeers, other.OfflinePeers)
	nm.FirewallRules = util.MergeUnique(nm.FirewallRules, other.FirewallRules)
	nm.RoutesFirewallRules = util.MergeUnique(nm.RoutesFirewallRules, other.RoutesFirewallRules)
	nm.ForwardingRules = util.MergeUnique(nm.ForwardingRules, other.ForwardingRules)
}

// TODO optimize
func mergeUniquePeersByID(peers1, peers2 []*nbpeer.Peer) []*nbpeer.Peer {
	result := make(map[string]*nbpeer.Peer)
	for _, peer := range peers1 {
		result[peer.ID] = peer
	}
	for _, peer := range peers2 {
		if _, ok := result[peer.ID]; !ok {
			result[peer.ID] = peer
		}
	}

	return maps.Values(result)
}

// GetPeerNetworkMap returns the networkmap for the given peer ID.
func (a *Account) GetPeerNetworkMap(
	ctx context.Context,
	peerID string,
	peersCustomZone nbdns.CustomZone,
	validatedPeersMap map[string]struct{},
	resourcePolicies map[string][]*Policy,
	routers map[string]map[string]*routerTypes.NetworkRouter,
	metrics *telemetry.AccountManagerMetrics,
) *NetworkMap {
	start := time.Now()

	peer := a.Peers[peerID]
	if peer == nil {
		return &NetworkMap{
			Network: a.Network.Copy(),
		}
	}

	if _, ok := validatedPeersMap[peerID]; !ok {
		return &NetworkMap{
			Network: a.Network.Copy(),
		}
	}

	aclPeers, firewallRules := a.GetPeerConnectionResources(ctx, peer, validatedPeersMap)
	// exclude expired peers
	var peersToConnect []*nbpeer.Peer
	var expiredPeers []*nbpeer.Peer
	for _, p := range aclPeers {
		expired, _ := p.LoginExpired(a.Settings.PeerLoginExpiration)
		if a.Settings.PeerLoginExpirationEnabled && expired {
			expiredPeers = append(expiredPeers, p)
			continue
		}
		peersToConnect = append(peersToConnect, p)
	}

	routesUpdate := a.GetRoutesToSync(ctx, peerID, peersToConnect)
	routesFirewallRules := a.GetPeerRoutesFirewallRules(ctx, peerID, validatedPeersMap)
	isRouter, networkResourcesRoutes, sourcePeers := a.GetNetworkResourcesRoutesToSync(ctx, peerID, resourcePolicies, routers)
	var networkResourcesFirewallRules []*RouteFirewallRule
	if isRouter {
		networkResourcesFirewallRules = a.GetPeerNetworkResourceFirewallRules(ctx, peer, validatedPeersMap, networkResourcesRoutes, resourcePolicies)
	}
	peersToConnectIncludingRouters := a.addNetworksRoutingPeers(networkResourcesRoutes, peer, peersToConnect, expiredPeers, isRouter, sourcePeers)

	dnsManagementStatus := a.getPeerDNSManagementStatus(peerID)
	dnsUpdate := nbdns.Config{
		ServiceEnable: dnsManagementStatus,
	}

	if dnsManagementStatus {
		var zones []nbdns.CustomZone

		if peersCustomZone.Domain != "" {
			records := filterZoneRecordsForPeers(peer, peersCustomZone, peersToConnect)
			zones = append(zones, nbdns.CustomZone{
				Domain:  peersCustomZone.Domain,
				Records: records,
			})
		}
		dnsUpdate.CustomZones = zones
		dnsUpdate.NameServerGroups = getPeerNSGroups(a, peerID)
	}

	nm := &NetworkMap{
		Peers:               peersToConnectIncludingRouters,
		Network:             a.Network.Copy(),
		Routes:              slices.Concat(networkResourcesRoutes, routesUpdate),
		DNSConfig:           dnsUpdate,
		OfflinePeers:        expiredPeers,
		FirewallRules:       firewallRules,
		RoutesFirewallRules: slices.Concat(networkResourcesFirewallRules, routesFirewallRules),
	}

	if metrics != nil {
		objectCount := int64(len(peersToConnectIncludingRouters) + len(expiredPeers) + len(routesUpdate) + len(networkResourcesRoutes) + len(firewallRules) + +len(networkResourcesFirewallRules) + len(routesFirewallRules))
		metrics.CountNetworkMapObjects(objectCount)
		metrics.CountGetPeerNetworkMapDuration(time.Since(start))

		if objectCount > 5000 {
			log.WithContext(ctx).Tracef("account: %s has a total resource count of %d objects, "+
				"peers to connect: %d, expired peers: %d, routes: %d, firewall rules: %d, network resources routes: %d, network resources firewall rules: %d, routes firewall rules: %d",
				a.Id, objectCount, len(peersToConnectIncludingRouters), len(expiredPeers), len(routesUpdate), len(firewallRules), len(networkResourcesRoutes), len(networkResourcesFirewallRules), len(routesFirewallRules))
		}
	}

	return nm
}

// GetPeerConnectionResources for a given peer
//
// This function returns the list of peers and firewall rules that are applicable to a given peer.
func (a *Account) GetPeerConnectionResources(ctx context.Context, peer *nbpeer.Peer, validatedPeersMap map[string]struct{}) ([]*nbpeer.Peer, []*FirewallRule) {
	generateResources, getAccumulatedResources := a.connResourcesGenerator(ctx, peer)

	for _, policy := range a.Policies {
		if !policy.Enabled {
			continue
		}

		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			sourcePeers, peerInSources := a.getAllPeersFromGroups(ctx, rule.Sources, peer.ID, policy.SourcePostureChecks, validatedPeersMap)
			destinationPeers, peerInDestinations := a.getAllPeersFromGroups(ctx, rule.Destinations, peer.ID, nil, validatedPeersMap)

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
		}
	}

	return getAccumulatedResources()
}

// connResourcesGenerator returns generator and accumulator function which returns the result of generator calls
//
// The generator function is used to generate the list of peers and firewall rules that are applicable to a given peer.
// It safe to call the generator function multiple times for same peer and different rules no duplicates will be
// generated. The accumulator function returns the result of all the generator calls.
func (a *Account) connResourcesGenerator(ctx context.Context, targetPeer *nbpeer.Peer) (func(*PolicyRule, []*nbpeer.Peer, int), func() ([]*nbpeer.Peer, []*FirewallRule)) {
	rulesExists := make(map[string]struct{})
	peersExists := make(map[string]struct{})
	rules := make([]*FirewallRule, 0)
	peers := make([]*nbpeer.Peer, 0)

	all, err := a.GetGroupAll()
	if err != nil {
		log.WithContext(ctx).Errorf("failed to get group all: %v", err)
		all = &Group{}
	}

	return func(rule *PolicyRule, groupPeers []*nbpeer.Peer, direction int) {
			isAll := (len(all.Peers) - 1) == len(groupPeers)
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
					PeerIP:    peer.IP.String(),
					Direction: direction,
					Action:    string(rule.Action),
					Protocol:  string(rule.Protocol),
				}

				if isAll {
					fr.PeerIP = "0.0.0.0"
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

				rules = append(rules, expandPortsAndRanges(fr, rule, targetPeer)...)
			}
		}, func() ([]*nbpeer.Peer, []*FirewallRule) {
			return peers, rules
		}
}

// getAllPeersFromGroups for given peer ID and list of groups
//
// Returns a list of peers from specified groups that pass specified posture checks
// and a boolean indicating if the supplied peer ID exists within these groups.
//
// Important: Posture checks are applicable only to source group peers,
// for destination group peers, call this method with an empty list of sourcePostureChecksIDs
func (a *Account) getAllPeersFromGroups(ctx context.Context, groups []string, peerID string, sourcePostureChecksIDs []string, validatedPeersMap map[string]struct{}) ([]*nbpeer.Peer, bool) {
	peerInGroups := false
	uniquePeerIDs := a.getUniquePeerIDsFromGroupsIDs(ctx, groups)
	filteredPeers := make([]*nbpeer.Peer, 0, len(uniquePeerIDs))
	for _, p := range uniquePeerIDs {
		peer, ok := a.Peers[p]
		if !ok || peer == nil {
			continue
		}

		// validate the peer based on policy posture checks applied
		isValid := a.validatePostureChecksOnPeer(ctx, sourcePostureChecksIDs, peer.ID)
		if !isValid {
			continue
		}

		if _, ok := validatedPeersMap[peer.ID]; !ok {
			continue
		}

		if peer.ID == peerID {
			peerInGroups = true
			continue
		}

		filteredPeers = append(filteredPeers, peer)
	}

	return filteredPeers, peerInGroups
}

// validatePostureChecksOnPeer validates the posture checks on a peer
func (a *Account) validatePostureChecksOnPeer(ctx context.Context, sourcePostureChecksID []string, peerID string) bool {
	peer, ok := a.Peers[peerID]
	if !ok && peer == nil {
		return false
	}

	for _, postureChecksID := range sourcePostureChecksID {
		postureChecks := a.GetPostureChecks(postureChecksID)
		if postureChecks == nil {
			continue
		}

		for _, check := range postureChecks.GetChecks() {
			isValid, err := check.Check(ctx, *peer)
			if err != nil {
				log.WithContext(ctx).Debugf("an error occurred check %s: on peer: %s :%s", check.Name(), peer.ID, err.Error())
			}
			if !isValid {
				return false
			}
		}
	}
	return true
}

// expandPortsAndRanges expands Ports and PortRanges of a rule into individual firewall rules
func expandPortsAndRanges(base FirewallRule, rule *PolicyRule, peer *nbpeer.Peer) []*FirewallRule {
	var expanded []*FirewallRule

	if len(rule.Ports) > 0 {
		for _, port := range rule.Ports {
			fr := base
			fr.Port = port
			expanded = append(expanded, &fr)
		}
		return expanded
	}

	supportPortRanges := peerSupportsPortRanges(peer.Meta.WtVersion)
	for _, portRange := range rule.PortRanges {
		fr := base

		if supportPortRanges {
			fr.PortRange = portRange
		} else {
			// Peer doesn't support port ranges, only allow single-port ranges
			if portRange.Start != portRange.End {
				continue
			}
			fr.Port = strconv.FormatUint(uint64(portRange.Start), 10)
		}
		expanded = append(expanded, &fr)
	}

	return expanded
}

// peerSupportsPortRanges checks if the peer version supports port ranges.
func peerSupportsPortRanges(peerVer string) bool {
	if strings.Contains(peerVer, "dev") {
		return true
	}

	meetMinVer, err := posture.MeetsMinVersion(firewallRuleMinPortRangesVer, peerVer)
	return err == nil && meetMinVer
}

// GetNetworkResourcesRoutesToSync returns network routes for syncing with a specific peer and its ACL peers.
func (a *Account) GetNetworkResourcesRoutesToSync(ctx context.Context, peerID string, resourcePolicies map[string][]*Policy, routers map[string]map[string]*routerTypes.NetworkRouter) (bool, []*route.Route, map[string]struct{}) {
	var isRoutingPeer bool
	var routes []*route.Route
	allSourcePeers := make(map[string]struct{}, len(a.Peers))

	for _, resource := range a.NetworkResources {
		if !resource.Enabled {
			continue
		}

		var addSourcePeers bool

		networkRoutingPeers, exists := routers[resource.NetworkID]
		if exists {
			if router, ok := networkRoutingPeers[peerID]; ok {
				isRoutingPeer, addSourcePeers = true, true
				routes = append(routes, a.getNetworkResourcesRoutes(resource, peerID, router, resourcePolicies)...)
			}
		}

		addedResourceRoute := false
		for _, policy := range resourcePolicies[resource.ID] {
			peers := a.getUniquePeerIDsFromGroupsIDs(ctx, policy.SourceGroups())
			if addSourcePeers {
				for _, pID := range a.getPostureValidPeers(peers, policy.SourcePostureChecks) {
					allSourcePeers[pID] = struct{}{}
				}
			} else if slices.Contains(peers, peerID) && a.validatePostureChecksOnPeer(ctx, policy.SourcePostureChecks, peerID) {
				// add routes for the resource if the peer is in the distribution group
				for peerId, router := range networkRoutingPeers {
					routes = append(routes, a.getNetworkResourcesRoutes(resource, peerId, router, resourcePolicies)...)
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

// getNetworkResourcesRoutes convert the network resources list to routes list.
func (a *Account) getNetworkResourcesRoutes(resource *resourceTypes.NetworkResource, peerId string, router *routerTypes.NetworkRouter, resourcePolicies map[string][]*Policy) []*route.Route {
	resourceAppliedPolicies := resourcePolicies[resource.ID]

	var routes []*route.Route
	// distribute the resource routes only if there is policy applied to it
	if len(resourceAppliedPolicies) > 0 {
		peer := a.GetPeer(peerId)
		if peer != nil {
			routes = append(routes, resource.ToRoute(peer, router))
		}
	}

	return routes
}

func (a *Account) getPostureValidPeers(inputPeers []string, postureChecksIDs []string) []string {
	var dest []string
	for _, peerID := range inputPeers {
		if a.validatePostureChecksOnPeer(context.Background(), postureChecksIDs, peerID) {
			dest = append(dest, peerID)
		}
	}
	return dest
}

func (a *Account) getUniquePeerIDsFromGroupsIDs(ctx context.Context, groups []string) []string {
	peerIDs := make(map[string]struct{}, len(groups)) // we expect at least one peer per group as initial capacity
	for _, groupID := range groups {
		group := a.GetGroup(groupID)
		if group == nil {
			log.WithContext(ctx).Warnf("group %s doesn't exist under account %s, will continue map generation without it", groupID, a.Id)
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

// GetPeerRoutesFirewallRules gets the routes firewall rules associated with a routing peer ID for the account.
func (a *Account) GetPeerRoutesFirewallRules(ctx context.Context, peerID string, validatedPeersMap map[string]struct{}) []*RouteFirewallRule {
	routesFirewallRules := make([]*RouteFirewallRule, 0, len(a.Routes))

	enabledRoutes, _ := a.getRoutingPeerRoutes(ctx, peerID)
	for _, route := range enabledRoutes {
		// If no access control groups are specified, accept all traffic.
		if len(route.AccessControlGroups) == 0 {
			defaultPermit := getDefaultPermit(route)
			routesFirewallRules = append(routesFirewallRules, defaultPermit...)
			continue
		}

		distributionPeers := a.getDistributionGroupsPeers(route)

		for _, accessGroup := range route.AccessControlGroups {
			policies := GetAllRoutePoliciesFromGroups(a, []string{accessGroup})
			rules := a.getRouteFirewallRules(ctx, peerID, policies, route, validatedPeersMap, distributionPeers)
			routesFirewallRules = append(routesFirewallRules, rules...)
		}
	}

	return routesFirewallRules
}

func (a *Account) getRouteFirewallRules(ctx context.Context, peerID string, policies []*Policy, route *route.Route, validatedPeersMap map[string]struct{}, distributionPeers map[string]struct{}) []*RouteFirewallRule {
	var fwRules []*RouteFirewallRule
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}

		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			rulePeers := a.getRulePeers(rule, policy.SourcePostureChecks, peerID, distributionPeers, validatedPeersMap)
			rules := generateRouteFirewallRules(ctx, route, rule, rulePeers, FirewallRuleDirectionIN)
			fwRules = append(fwRules, rules...)
		}
	}
	return fwRules
}

func (a *Account) getRulePeers(rule *PolicyRule, postureChecks []string, peerID string, distributionPeers map[string]struct{}, validatedPeersMap map[string]struct{}) []*nbpeer.Peer {
	distPeersWithPolicy := make(map[string]struct{})
	for _, id := range rule.Sources {
		group := a.Groups[id]
		if group == nil {
			continue
		}

		for _, pID := range group.Peers {
			if pID == peerID {
				continue
			}
			_, distPeer := distributionPeers[pID]
			_, valid := validatedPeersMap[pID]
			if distPeer && valid && a.validatePostureChecksOnPeer(context.Background(), postureChecks, pID) {
				distPeersWithPolicy[pID] = struct{}{}
			}
		}
	}

	distributionGroupPeers := make([]*nbpeer.Peer, 0, len(distPeersWithPolicy))
	for pID := range distPeersWithPolicy {
		peer := a.Peers[pID]
		if peer == nil {
			continue
		}
		distributionGroupPeers = append(distributionGroupPeers, peer)
	}
	return distributionGroupPeers
}

func (a *Account) getDistributionGroupsPeers(route *route.Route) map[string]struct{} {
	distPeers := make(map[string]struct{})
	for _, id := range route.Groups {
		group := a.Groups[id]
		if group == nil {
			continue
		}

		for _, pID := range group.Peers {
			distPeers[pID] = struct{}{}
		}
	}
	return distPeers
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
		Domains:      route.Domains,
		IsDynamic:    route.IsDynamic(),
		RouteID:      route.ID,
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

// GetAllRoutePoliciesFromGroups retrieves route policies associated with the specified access control groups
// and returns a list of policies that have rules with destinations matching the specified groups.
func GetAllRoutePoliciesFromGroups(account *Account, accessControlGroups []string) []*Policy {
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

// GetPeerNetworkResourceFirewallRules gets the network resources firewall rules associated with a routing peer ID for the account.
func (a *Account) GetPeerNetworkResourceFirewallRules(ctx context.Context, peer *nbpeer.Peer, validatedPeersMap map[string]struct{}, routes []*route.Route, resourcePolicies map[string][]*Policy) []*RouteFirewallRule {
	routesFirewallRules := make([]*RouteFirewallRule, 0)

	for _, route := range routes {
		if route.Peer != peer.Key {
			continue
		}
		resourceAppliedPolicies := resourcePolicies[string(route.GetResourceID())]
		distributionPeers := getPoliciesSourcePeers(resourceAppliedPolicies, a.Groups)

		rules := a.getRouteFirewallRules(ctx, peer.ID, resourceAppliedPolicies, route, validatedPeersMap, distributionPeers)
		for _, rule := range rules {
			if len(rule.SourceRanges) > 0 {
				routesFirewallRules = append(routesFirewallRules, rule)
			}
		}
	}

	return routesFirewallRules
}

// getPoliciesSourcePeers collects all unique peers from the source groups defined in the given policies.
func getPoliciesSourcePeers(policies []*Policy, groups map[string]*Group) map[string]struct{} {
	sourcePeers := make(map[string]struct{})

	for _, policy := range policies {
		for _, rule := range policy.Rules {
			for _, sourceGroup := range rule.Sources {
				group := groups[sourceGroup]
				if group == nil {
					continue
				}

				for _, peer := range group.Peers {
					sourcePeers[peer] = struct{}{}
				}
			}
		}
	}

	return sourcePeers
}

// GetRoutesToSync returns the enabled routes for the peer ID and the routes
// from the ACL peers that have distribution groups associated with the peer ID.
// Please mind, that the returned route.Route objects will contain Peer.Key instead of Peer.ID.
func (a *Account) GetRoutesToSync(ctx context.Context, peerID string, aclPeers []*nbpeer.Peer) []*route.Route {
	routes, peerDisabledRoutes := a.getRoutingPeerRoutes(ctx, peerID)
	peerRoutesMembership := make(LookupMap)
	for _, r := range append(routes, peerDisabledRoutes...) {
		peerRoutesMembership[string(r.GetHAUniqueID())] = struct{}{}
	}

	groupListMap := a.GetPeerGroups(peerID)
	for _, peer := range aclPeers {
		activeRoutes, _ := a.getRoutingPeerRoutes(ctx, peer.ID)
		groupFilteredRoutes := a.filterRoutesByGroups(activeRoutes, groupListMap)
		filteredRoutes := a.filterRoutesFromPeersOfSameHAGroup(groupFilteredRoutes, peerRoutesMembership)
		routes = append(routes, filteredRoutes...)
	}

	return routes
}

func (a *Account) GetPeerGroups(peerID string) LookupMap {
	groupList := make(LookupMap)
	for groupID, group := range a.Groups {
		for _, id := range group.Peers {
			if id == peerID {
				groupList[groupID] = struct{}{}
				break
			}
		}
	}
	return groupList
}

// filterRoutesFromPeersOfSameHAGroup filters and returns a list of routes that don't share the same HA route membership
func (a *Account) filterRoutesFromPeersOfSameHAGroup(routes []*route.Route, peerMemberships LookupMap) []*route.Route {
	var filteredRoutes []*route.Route
	for _, r := range routes {
		_, found := peerMemberships[string(r.GetHAUniqueID())]
		if !found {
			filteredRoutes = append(filteredRoutes, r)
		}
	}
	return filteredRoutes
}

// filterRoutesByGroups returns a list with routes that have distribution groups in the group's map
func (a *Account) filterRoutesByGroups(routes []*route.Route, groupListMap LookupMap) []*route.Route {
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

// getRoutingPeerRoutes returns the enabled and disabled lists of routes that the given routing peer serves
// Please mind, that the returned route.Route objects will contain Peer.Key instead of Peer.ID.
// If the given is not a routing peer, then the lists are empty.
func (a *Account) getRoutingPeerRoutes(ctx context.Context, peerID string) (enabledRoutes []*route.Route, disabledRoutes []*route.Route) {

	peer := a.GetPeer(peerID)
	if peer == nil {
		// log.WithContext(ctx).Errorf("peer %s that doesn't exist under account %s", peerID, a.Id)
		return enabledRoutes, disabledRoutes
	}

	seenRoute := make(map[route.ID]struct{})

	takeRoute := func(r *route.Route, id string) {
		if _, ok := seenRoute[r.ID]; ok {
			return
		}
		seenRoute[r.ID] = struct{}{}

		if r.Enabled {
			r.Peer = peer.Key
			enabledRoutes = append(enabledRoutes, r)
			return
		}
		disabledRoutes = append(disabledRoutes, r)
	}

	for _, r := range a.Routes {
		for _, groupID := range r.PeerGroups {
			group := a.GetGroup(groupID)
			if group == nil {
				log.WithContext(ctx).Errorf("route %s has peers group %s that doesn't exist under account %s", r.ID, groupID, a.Id)
				continue
			}
			for _, id := range group.Peers {
				if id != peerID {
					continue
				}

				newPeerRoute := r.Copy()
				newPeerRoute.Peer = id
				newPeerRoute.PeerGroups = nil
				newPeerRoute.ID = route.ID(string(r.ID) + ":" + id) // we have to provide unique route id when distribute network map
				takeRoute(newPeerRoute, id)
				break
			}
		}
		if r.Peer == peerID {
			takeRoute(r.Copy(), peerID)
		}
	}

	return enabledRoutes, disabledRoutes
}

func (a *Account) addNetworksRoutingPeers(
	networkResourcesRoutes []*route.Route,
	peer *nbpeer.Peer,
	peersToConnect []*nbpeer.Peer,
	expiredPeers []*nbpeer.Peer,
	isRouter bool,
	sourcePeers map[string]struct{},
) []*nbpeer.Peer {

	networkRoutesPeers := make(map[string]struct{}, len(networkResourcesRoutes))
	for _, r := range networkResourcesRoutes {
		networkRoutesPeers[r.PeerID] = struct{}{}
	}

	delete(sourcePeers, peer.ID)
	delete(networkRoutesPeers, peer.ID)

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
		if missingPeer := a.Peers[p]; missingPeer != nil {
			peersToConnect = append(peersToConnect, missingPeer)
		}
	}

	return peersToConnect
}

func (a *Account) getPeerDNSManagementStatus(peerID string) bool {
	peerGroups := a.GetPeerGroups(peerID)
	enabled := true
	for _, groupID := range a.DNSSettings.DisabledManagementGroups {
		_, found := peerGroups[groupID]
		if found {
			enabled = false
			break
		}
	}
	return enabled
}

func getPeerNSGroups(account *Account, peerID string) []*nbdns.NameServerGroup {
	groupList := account.GetPeerGroups(peerID)

	var peerNSGroups []*nbdns.NameServerGroup

	for _, nsGroup := range account.NameServerGroups {
		if !nsGroup.Enabled {
			continue
		}
		for _, gID := range nsGroup.Groups {
			_, found := groupList[gID]
			if found {
				if !peerIsNameserver(account.GetPeer(peerID), nsGroup) {
					peerNSGroups = append(peerNSGroups, nsGroup.Copy())
					break
				}
			}
		}
	}

	return peerNSGroups
}

// peerIsNameserver returns true if the peer is a nameserver for a nsGroup
func peerIsNameserver(peer *nbpeer.Peer, nsGroup *nbdns.NameServerGroup) bool {
	for _, ns := range nsGroup.NameServers {
		if peer.IP.Equal(ns.IP.AsSlice()) {
			return true
		}
	}
	return false
}

func (a *Account) initNetworkMapBuilder(validatedPeers map[string]struct{}) {
	if a.NetworkMapCache != nil {
		return
	}
	a.NetworkMapCache = NewNetworkMapBuilder(a, validatedPeers)
}

func (a *Account) InitNetworkMapBuilderIfNeeded(validatedPeers map[string]struct{}) {
	a.initNetworkMapBuilder(validatedPeers)
}

func (a *Account) GetPeerNetworkMapExp(
	ctx context.Context,
	peerID string,
	peersCustomZone nbdns.CustomZone,
	validatedPeers map[string]struct{},
	metrics *telemetry.AccountManagerMetrics,
) *NetworkMap {
	a.initNetworkMapBuilder(validatedPeers)
	return a.NetworkMapCache.GetPeerNetworkMap(ctx, peerID, peersCustomZone, validatedPeers, metrics)
}

func (a *Account) OnPeerAddedUpdNetworkMapCache(peerId string) error {
	if a.NetworkMapCache == nil {
		return nil
	}
	return a.NetworkMapCache.OnPeerAddedIncremental(peerId)
}

func (a *Account) OnPeerDeletedUpdNetworkMapCache(peerId string) error {
	if a.NetworkMapCache == nil {
		return nil
	}
	return a.NetworkMapCache.OnPeerDeleted(peerId)
}

func (a *Account) UpdatePeerInNetworkMapCache(peer *nbpeer.Peer) {
	if a.NetworkMapCache == nil {
		return
	}
	a.NetworkMapCache.UpdatePeer(peer)
}

func (a *Account) RecalculateNetworkMapCache(validatedPeers map[string]struct{}) {
	a.initNetworkMapBuilder(validatedPeers)
}

// filterZoneRecordsForPeers filters DNS records to only include peers to connect.
func filterZoneRecordsForPeers(peer *nbpeer.Peer, customZone nbdns.CustomZone, peersToConnect []*nbpeer.Peer) []nbdns.SimpleRecord {
	filteredRecords := make([]nbdns.SimpleRecord, 0, len(customZone.Records))
	peerIPs := make(map[string]struct{})

	// Add peer's own IP to include its own DNS records
	peerIPs[peer.IP.String()] = struct{}{}

	for _, peerToConnect := range peersToConnect {
		peerIPs[peerToConnect.IP.String()] = struct{}{}
	}

	for _, record := range customZone.Records {
		if _, exists := peerIPs[record.RData]; exists {
			filteredRecords = append(filteredRecords, record)
		}
	}

	return filteredRecords
}
