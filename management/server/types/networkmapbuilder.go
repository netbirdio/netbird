package types

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"

	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/route"
)

const (
	allPeers = "0.0.0.0"
)

type NetworkMapCache struct {
	globalRoutes     map[route.ID]*route.Route
	globalRules      map[string]*FirewallRule      //ruleId
	globalRouteRules map[string]*RouteFirewallRule //ruleId
	globalPeers      map[string]*nbpeer.Peer

	groupToPeers    map[string][]string
	peerToGroups    map[string][]string
	policyToRules   map[string][]*PolicyRule //policyId
	groupToPolicies map[string][]*Policy
	groupToRoutes   map[string][]*route.Route
	peerToRoutes    map[string][]*route.Route

	peerACLs   map[string]*PeerACLView
	peerRoutes map[string]*PeerRoutesView
	peerDNS    map[string]*nbdns.Config

	resourceRouters  map[string]map[string]*routerTypes.NetworkRouter
	resourcePolicies map[string][]*Policy

	globalResources map[string]*resourceTypes.NetworkResource // resourceId

	mu sync.RWMutex
}

type PeerACLView struct {
	ConnectedPeerIDs []string
	FirewallRuleIDs  []string
}

type PeerRoutesView struct {
	OwnRouteIDs          []route.ID
	NetworkResourceIDs   []route.ID
	InheritedRouteIDs    []route.ID
	RouteFirewallRuleIDs []string
}

type NetworkMapBuilder struct {
	account        atomic.Pointer[Account]
	cache          *NetworkMapCache
	validatedPeers map[string]struct{}
}

func NewNetworkMapBuilder(account *Account, validatedPeers map[string]struct{}) *NetworkMapBuilder {
	builder := &NetworkMapBuilder{
		cache: &NetworkMapCache{
			globalRoutes:     make(map[route.ID]*route.Route),
			globalRules:      make(map[string]*FirewallRule),
			globalRouteRules: make(map[string]*RouteFirewallRule),
			globalPeers:      make(map[string]*nbpeer.Peer),
			groupToPeers:     make(map[string][]string),
			peerToGroups:     make(map[string][]string),
			policyToRules:    make(map[string][]*PolicyRule),
			groupToPolicies:  make(map[string][]*Policy),
			groupToRoutes:    make(map[string][]*route.Route),
			peerToRoutes:     make(map[string][]*route.Route),
			peerACLs:         make(map[string]*PeerACLView),
			peerRoutes:       make(map[string]*PeerRoutesView),
			peerDNS:          make(map[string]*nbdns.Config),
			globalResources:  make(map[string]*resourceTypes.NetworkResource),
		},
		validatedPeers: make(map[string]struct{}),
	}
	builder.account.Store(account)
	maps.Copy(builder.validatedPeers, validatedPeers)

	builder.initialBuild(account)

	return builder
}

func (b *NetworkMapBuilder) initialBuild(account *Account) {
	b.cache.mu.Lock()
	defer b.cache.mu.Unlock()

	start := time.Now()

	b.buildGlobalIndexes(account)

	resourceRouters := account.GetResourceRoutersMap()
	resourcePolicies := account.GetResourcePoliciesMap()
	b.cache.resourceRouters = resourceRouters
	b.cache.resourcePolicies = resourcePolicies

	for peerID := range account.Peers {
		b.buildPeerACLView(account, peerID)
		b.buildPeerRoutesView(account, peerID)
		b.buildPeerDNSView(account, peerID)
	}

	log.Debugf("NetworkMapBuilder: Initial build completed in %v for account %s", time.Since(start), account.Id)
}

func (b *NetworkMapBuilder) buildGlobalIndexes(account *Account) {
	clear(b.cache.globalPeers)
	clear(b.cache.groupToPeers)
	clear(b.cache.peerToGroups)
	clear(b.cache.policyToRules)
	clear(b.cache.groupToPolicies)
	clear(b.cache.globalRoutes)
	clear(b.cache.globalRules)
	clear(b.cache.globalRouteRules)
	clear(b.cache.globalResources)
	clear(b.cache.groupToRoutes)
	clear(b.cache.peerToRoutes)

	maps.Copy(b.cache.globalPeers, account.Peers)

	for groupID, group := range account.Groups {
		peersCopy := make([]string, len(group.Peers))
		copy(peersCopy, group.Peers)
		b.cache.groupToPeers[groupID] = peersCopy

		for _, peerID := range group.Peers {
			b.cache.peerToGroups[peerID] = append(b.cache.peerToGroups[peerID], groupID)
		}
	}

	for _, policy := range account.Policies {
		if !policy.Enabled {
			continue
		}

		b.cache.policyToRules[policy.ID] = policy.Rules

		affectedGroups := make(map[string]struct{})
		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			for _, groupID := range rule.Sources {
				affectedGroups[groupID] = struct{}{}
			}
			for _, groupID := range rule.Destinations {
				affectedGroups[groupID] = struct{}{}
			}
		}

		for groupID := range affectedGroups {
			b.cache.groupToPolicies[groupID] = append(b.cache.groupToPolicies[groupID], policy)
		}
	}

	for _, resource := range account.NetworkResources {
		if !resource.Enabled {
			continue
		}
		b.cache.globalResources[resource.ID] = resource
	}

	for _, r := range account.Routes {
		if !r.Enabled {
			continue
		}
		for _, groupID := range r.PeerGroups {
			b.cache.groupToRoutes[groupID] = append(b.cache.groupToRoutes[groupID], r)
		}
		if r.Peer != "" {
			if peer, ok := b.cache.globalPeers[r.Peer]; ok {
				b.cache.peerToRoutes[peer.ID] = append(b.cache.peerToRoutes[peer.ID], r)
			}
		}
	}
}

func (b *NetworkMapBuilder) buildPeerACLView(account *Account, peerID string) {
	peer := account.GetPeer(peerID)
	if peer == nil {
		return
	}

	allPotentialPeers, firewallRules := b.getPeerConnectionResources(account, peerID, b.validatedPeers)

	isRouter, networkResourcesRoutes, sourcePeers := b.getNetworkResourcesForPeer(account, peerID)

	var emptyExpiredPeers []*nbpeer.Peer
	finalAllPeers := b.addNetworksRoutingPeers(
		networkResourcesRoutes,
		peer,
		allPotentialPeers,
		emptyExpiredPeers,
		isRouter,
		sourcePeers,
	)

	view := &PeerACLView{
		ConnectedPeerIDs: make([]string, 0, len(finalAllPeers)),
		FirewallRuleIDs:  make([]string, 0, len(firewallRules)),
	}

	for _, p := range finalAllPeers {
		view.ConnectedPeerIDs = append(view.ConnectedPeerIDs, p.ID)
	}

	for _, rule := range firewallRules {
		ruleID := b.generateFirewallRuleID(rule)
		view.FirewallRuleIDs = append(view.FirewallRuleIDs, ruleID)
		b.cache.globalRules[ruleID] = rule
	}

	b.cache.peerACLs[peerID] = view
}

func (b *NetworkMapBuilder) getPeerConnectionResources(account *Account, peerID string,
	validatedPeersMap map[string]struct{},
) ([]*nbpeer.Peer, []*FirewallRule) {
	ctx := context.Background()
	peer := b.cache.globalPeers[peerID]
	if peer == nil {
		return nil, nil
	}

	peerGroups := b.cache.peerToGroups[peerID]
	peerGroupsMap := make(map[string]struct{}, len(peerGroups))
	for _, groupID := range peerGroups {
		peerGroupsMap[groupID] = struct{}{}
	}

	rulesExists := make(map[string]struct{})
	peersExists := make(map[string]struct{})
	fwRules := make([]*FirewallRule, 0)
	peers := make([]*nbpeer.Peer, 0)

	for _, group := range peerGroups {
		policies := b.cache.groupToPolicies[group]
		for _, policy := range policies {
			if isValid := account.validatePostureChecksOnPeer(ctx, policy.SourcePostureChecks, peerID); !isValid {
				continue
			}
			rules := b.cache.policyToRules[policy.ID]
			for _, rule := range rules {
				peerInSources := b.isPeerInGroupscached(rule.Sources, peerGroupsMap)
				peerInDestinations := b.isPeerInGroupscached(rule.Destinations, peerGroupsMap)

				if !peerInSources && !peerInDestinations {
					continue
				}

				var sourcePeers []*nbpeer.Peer
				if peerInDestinations {
					sourcePeers = b.getPeersFromGroupscached(account, rule.Sources, peerID, policy.SourcePostureChecks, validatedPeersMap)
				}

				var destinationPeers []*nbpeer.Peer
				if peerInSources {
					destinationPeers = b.getPeersFromGroupscached(account, rule.Destinations, peerID, nil, validatedPeersMap)
				}

				if rule.Bidirectional {
					if peerInSources {
						b.generateResourcescached(
							account, rule, destinationPeers, FirewallRuleDirectionIN,
							peer, &peers, &fwRules, peersExists, rulesExists,
						)
					}
					if peerInDestinations {
						b.generateResourcescached(
							account, rule, sourcePeers, FirewallRuleDirectionOUT,
							peer, &peers, &fwRules, peersExists, rulesExists,
						)
					}
				}

				if peerInSources {
					b.generateResourcescached(
						account, rule, destinationPeers, FirewallRuleDirectionOUT,
						peer, &peers, &fwRules, peersExists, rulesExists,
					)
				}

				if peerInDestinations {
					b.generateResourcescached(
						account, rule, sourcePeers, FirewallRuleDirectionIN,
						peer, &peers, &fwRules, peersExists, rulesExists,
					)
				}
			}
		}
	}

	return peers, fwRules
}

func (b *NetworkMapBuilder) isPeerInGroupscached(groupIDs []string, peerGroupsMap map[string]struct{}) bool {
	for _, groupID := range groupIDs {
		if _, exists := peerGroupsMap[groupID]; exists {
			return true
		}
	}
	return false
}

func (b *NetworkMapBuilder) getPeersFromGroupscached(account *Account, groupIDs []string,
	excludePeerID string, postureChecksIDs []string, validatedPeersMap map[string]struct{},
) []*nbpeer.Peer {
	ctx := context.Background()
	uniquePeers := make(map[string]*nbpeer.Peer)

	for _, groupID := range groupIDs {
		peerIDs := b.cache.groupToPeers[groupID]
		for _, peerID := range peerIDs {
			if peerID == excludePeerID {
				continue
			}

			if _, ok := validatedPeersMap[peerID]; !ok {
				continue
			}

			peer := b.cache.globalPeers[peerID]
			if peer == nil {
				continue
			}

			if len(postureChecksIDs) > 0 {
				if !account.validatePostureChecksOnPeer(ctx, postureChecksIDs, peerID) {
					continue
				}
			}

			uniquePeers[peerID] = peer
		}
	}

	result := make([]*nbpeer.Peer, 0, len(uniquePeers))
	for _, peer := range uniquePeers {
		result = append(result, peer)
	}

	return result
}

func (b *NetworkMapBuilder) generateResourcescached(
	account *Account, rule *PolicyRule, groupPeers []*nbpeer.Peer, direction int, targetPeer *nbpeer.Peer,
	peers *[]*nbpeer.Peer, rules *[]*FirewallRule, peersExists map[string]struct{}, rulesExists map[string]struct{},
) {
	isAll := false
	if allGroup, err := account.GetGroupAll(); err == nil {
		isAll = (len(allGroup.Peers) - 1) == len(groupPeers)
	}

	for _, peer := range groupPeers {
		if peer == nil {
			continue
		}
		if _, ok := peersExists[peer.ID]; !ok {
			*peers = append(*peers, peer)
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
			fr.PeerIP = allPeers
		}

		var s strings.Builder
		s.WriteString(rule.ID)
		s.WriteString(fr.PeerIP)
		s.WriteString(strconv.Itoa(direction))
		s.WriteString(fr.Protocol)
		s.WriteString(fr.Action)
		s.WriteString(strings.Join(rule.Ports, ","))

		ruleID := s.String()

		if _, ok := rulesExists[ruleID]; ok {
			continue
		}
		rulesExists[ruleID] = struct{}{}

		if len(rule.Ports) == 0 && len(rule.PortRanges) == 0 {
			*rules = append(*rules, &fr)
			continue
		}

		*rules = append(*rules, expandPortsAndRanges(fr, rule, targetPeer)...)
	}
}

func (b *NetworkMapBuilder) getNetworkResourcesForPeer(account *Account, peerID string) (bool, []*route.Route, map[string]struct{}) {

	ctx := context.Background()

	var isRoutingPeer bool
	var routes []*route.Route
	allSourcePeers := make(map[string]struct{})

	peerGroups := b.cache.peerToGroups[peerID]
	peerGroupsMap := make(map[string]struct{}, len(peerGroups))
	for _, groupID := range peerGroups {
		peerGroupsMap[groupID] = struct{}{}
	}

	for _, resource := range b.cache.globalResources {

		networkRoutingPeers := b.cache.resourceRouters[resource.NetworkID]
		resourcePolicies := b.cache.resourcePolicies[resource.ID]
		if len(resourcePolicies) == 0 {
			continue
		}

		isRouterForThisResource := false

		if networkRoutingPeers != nil {
			if router, ok := networkRoutingPeers[peerID]; ok && router.Enabled {
				isRoutingPeer = true
				isRouterForThisResource = true
				if rt := b.createNetworkResourceRoutes(resource, peerID, router, resourcePolicies); rt != nil {
					routes = append(routes, rt)
				}
			}
		}

		hasAccessAsClient := false
		if !isRouterForThisResource {
			for _, policy := range resourcePolicies {
				if b.isPeerInGroupscached(policy.SourceGroups(), peerGroupsMap) {
					if account.validatePostureChecksOnPeer(ctx, policy.SourcePostureChecks, peerID) {
						hasAccessAsClient = true
						break
					}
				}
			}
		}

		if hasAccessAsClient && networkRoutingPeers != nil {
			for routerPeerID, router := range networkRoutingPeers {
				if router.Enabled {
					if rt := b.createNetworkResourceRoutes(resource, routerPeerID, router, resourcePolicies); rt != nil {
						routes = append(routes, rt)
					}
				}
			}
		}

		if isRouterForThisResource {
			for _, policy := range resourcePolicies {
				peersWithAccess := b.getPeersFromGroupscached(account, policy.SourceGroups(), "", policy.SourcePostureChecks, b.validatedPeers)
				for _, p := range peersWithAccess {
					allSourcePeers[p.ID] = struct{}{}
				}
			}
		}
	}

	return isRoutingPeer, routes, allSourcePeers
}

func (b *NetworkMapBuilder) createNetworkResourceRoutes(
	resource *resourceTypes.NetworkResource, routerPeerID string,
	router *routerTypes.NetworkRouter, resourcePolicies []*Policy,
) *route.Route {
	if len(resourcePolicies) > 0 {
		peer := b.cache.globalPeers[routerPeerID]
		if peer != nil {
			return resource.ToRoute(peer, router)
		}
	}
	return nil
}

func (b *NetworkMapBuilder) addNetworksRoutingPeers(
	networkResourcesRoutes []*route.Route, peer *nbpeer.Peer, peersToConnect []*nbpeer.Peer,
	expiredPeers []*nbpeer.Peer, isRouter bool, sourcePeers map[string]struct{},
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
		if missingPeer := b.cache.globalPeers[p]; missingPeer != nil {
			peersToConnect = append(peersToConnect, missingPeer)
		}
	}

	return peersToConnect
}

func (b *NetworkMapBuilder) buildPeerRoutesView(account *Account, peerID string) {
	ctx := context.Background()
	peer := account.GetPeer(peerID)
	if peer == nil {
		return
	}
	resourcePolicies := b.cache.resourcePolicies

	view := &PeerRoutesView{
		OwnRouteIDs:          make([]route.ID, 0),
		NetworkResourceIDs:   make([]route.ID, 0),
		RouteFirewallRuleIDs: make([]string, 0),
	}

	enabledRoutes, disabledRoutes := b.getRoutingPeerRoutes(peerID)
	for _, rt := range enabledRoutes {
		if rt.PeerID != "" && rt.PeerID != peerID {
			if b.cache.globalPeers[rt.PeerID] == nil {
				continue
			}
		}

		view.OwnRouteIDs = append(view.OwnRouteIDs, rt.ID)
		b.cache.globalRoutes[rt.ID] = rt
	}

	aclView := b.cache.peerACLs[peerID]
	if aclView != nil {
		peerRoutesMembership := make(LookupMap)
		for _, r := range append(enabledRoutes, disabledRoutes...) {
			peerRoutesMembership[string(r.GetHAUniqueID())] = struct{}{}
		}

		peerGroups := b.cache.peerToGroups[peerID]
		peerGroupsMap := make(LookupMap)
		for _, groupID := range peerGroups {
			peerGroupsMap[groupID] = struct{}{}
		}

		for _, aclPeerID := range aclView.ConnectedPeerIDs {
			if aclPeerID == peerID {
				continue
			}
			activeRoutes, _ := b.getRoutingPeerRoutes(aclPeerID)
			groupFilteredRoutes := account.filterRoutesByGroups(activeRoutes, peerGroupsMap)
			haFilteredRoutes := account.filterRoutesFromPeersOfSameHAGroup(groupFilteredRoutes, peerRoutesMembership)

			for _, inheritedRoute := range haFilteredRoutes {
				view.InheritedRouteIDs = append(view.InheritedRouteIDs, inheritedRoute.ID)
				b.cache.globalRoutes[inheritedRoute.ID] = inheritedRoute
			}
		}
	}

	_, networkResourcesRoutes, _ := b.getNetworkResourcesForPeer(account, peerID)

	for _, rt := range networkResourcesRoutes {
		view.NetworkResourceIDs = append(view.NetworkResourceIDs, rt.ID)
		b.cache.globalRoutes[rt.ID] = rt
	}

	routeFirewallRules := b.getPeerRoutesFirewallRules(account, peerID, b.validatedPeers)
	for _, rule := range routeFirewallRules {
		ruleID := b.generateRouteFirewallRuleID(rule)
		view.RouteFirewallRuleIDs = append(view.RouteFirewallRuleIDs, ruleID)
		b.cache.globalRouteRules[ruleID] = rule
	}

	if len(networkResourcesRoutes) > 0 {
		networkResourceFirewallRules := account.GetPeerNetworkResourceFirewallRules(ctx, peer, b.validatedPeers, networkResourcesRoutes, resourcePolicies)
		for _, rule := range networkResourceFirewallRules {
			ruleID := b.generateRouteFirewallRuleID(rule)
			view.RouteFirewallRuleIDs = append(view.RouteFirewallRuleIDs, ruleID)
			b.cache.globalRouteRules[ruleID] = rule
		}
	}

	b.cache.peerRoutes[peerID] = view
}

func (b *NetworkMapBuilder) getRoutingPeerRoutes(peerID string) (enabledRoutes []*route.Route, disabledRoutes []*route.Route) {
	peer := b.cache.globalPeers[peerID]
	if peer == nil {
		return enabledRoutes, disabledRoutes
	}

	seenRoute := make(map[route.ID]struct{})

	takeRoute := func(r *route.Route, id string) {
		if _, ok := seenRoute[r.ID]; ok {
			return
		}
		seenRoute[r.ID] = struct{}{}

		if r.Enabled {
			// maybe here is some mess - here we store peer key (see comment below)
			r.Peer = peer.Key
			enabledRoutes = append(enabledRoutes, r)
			return
		}
		disabledRoutes = append(disabledRoutes, r)
	}

	peerGroups := b.cache.peerToGroups[peerID]
	for _, groupID := range peerGroups {
		groupRoutes := b.cache.groupToRoutes[groupID]
		for _, r := range groupRoutes {
			newPeerRoute := r.Copy()
			// and here we store peer ID - this logic is taken from original account.getRoutingPeerRoutes
			newPeerRoute.Peer = peerID
			newPeerRoute.PeerGroups = nil
			newPeerRoute.ID = route.ID(string(r.ID) + ":" + peerID)
			takeRoute(newPeerRoute, peerID)
		}
	}
	for _, r := range b.cache.peerToRoutes[peerID] {
		takeRoute(r.Copy(), peerID)
	}
	return enabledRoutes, disabledRoutes
}

func (b *NetworkMapBuilder) getPeerRoutesFirewallRules(account *Account, peerID string, validatedPeersMap map[string]struct{}) []*RouteFirewallRule {
	routesFirewallRules := make([]*RouteFirewallRule, 0)

	enabledRoutes, _ := b.getRoutingPeerRoutes(peerID)
	for _, route := range enabledRoutes {
		if len(route.AccessControlGroups) == 0 {
			defaultPermit := getDefaultPermit(route)
			routesFirewallRules = append(routesFirewallRules, defaultPermit...)
			continue
		}

		distributionPeers := b.getDistributionGroupsPeers(route)

		for _, accessGroup := range route.AccessControlGroups {
			policies := b.getAllRoutePoliciesFromGroups([]string{accessGroup})

			rules := b.getRouteFirewallRules(peerID, policies, route, validatedPeersMap, distributionPeers, account)
			routesFirewallRules = append(routesFirewallRules, rules...)
		}
	}

	return routesFirewallRules
}

func (b *NetworkMapBuilder) getDistributionGroupsPeers(route *route.Route) map[string]struct{} {
	distPeers := make(map[string]struct{})
	for _, id := range route.Groups {
		groupPeers := b.cache.groupToPeers[id]
		if groupPeers == nil {
			continue
		}

		for _, pID := range groupPeers {
			distPeers[pID] = struct{}{}
		}
	}
	return distPeers
}

func (b *NetworkMapBuilder) getAllRoutePoliciesFromGroups(accessControlGroups []string) []*Policy {
	routePolicies := make(map[string]*Policy)

	for _, groupID := range accessControlGroups {
		candidatePolicies := b.cache.groupToPolicies[groupID]

		for _, policy := range candidatePolicies {
			if _, found := routePolicies[policy.ID]; found {
				continue
			}
			policyRules := b.cache.policyToRules[policy.ID]
			for _, rule := range policyRules {
				if slices.Contains(rule.Destinations, groupID) {
					routePolicies[policy.ID] = policy
					break
				}
			}
		}
	}

	return maps.Values(routePolicies)
}

func (b *NetworkMapBuilder) getRouteFirewallRules(
	peerID string, policies []*Policy, route *route.Route, validatedPeersMap map[string]struct{},
	distributionPeers map[string]struct{}, account *Account,
) []*RouteFirewallRule {
	ctx := context.Background()
	var fwRules []*RouteFirewallRule
	for _, policy := range policies {
		if !policy.Enabled {
			continue
		}

		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			rulePeers := b.getRulePeers(rule, policy.SourcePostureChecks, peerID, distributionPeers, validatedPeersMap, account)

			rules := generateRouteFirewallRules(ctx, route, rule, rulePeers, FirewallRuleDirectionIN)
			fwRules = append(fwRules, rules...)
		}
	}
	return fwRules
}

func (b *NetworkMapBuilder) getRulePeers(
	rule *PolicyRule, postureChecks []string, peerID string, distributionPeers map[string]struct{},
	validatedPeersMap map[string]struct{}, account *Account,
) []*nbpeer.Peer {
	distPeersWithPolicy := make(map[string]struct{})

	for _, id := range rule.Sources {
		groupPeers := b.cache.groupToPeers[id]
		if groupPeers == nil {
			continue
		}

		for _, pID := range groupPeers {
			if pID == peerID {
				continue
			}
			_, distPeer := distributionPeers[pID]
			_, valid := validatedPeersMap[pID]

			if distPeer && valid && account.validatePostureChecksOnPeer(context.Background(), postureChecks, pID) {
				distPeersWithPolicy[pID] = struct{}{}
			}
		}
	}

	distributionGroupPeers := make([]*nbpeer.Peer, 0, len(distPeersWithPolicy))
	for pID := range distPeersWithPolicy {
		peer := b.cache.globalPeers[pID]
		if peer == nil {
			continue
		}
		distributionGroupPeers = append(distributionGroupPeers, peer)
	}
	return distributionGroupPeers
}

func (b *NetworkMapBuilder) buildPeerDNSView(account *Account, peerID string) {
	peerGroups := b.cache.peerToGroups[peerID]
	checkGroups := make(map[string]struct{}, len(peerGroups))
	for _, groupID := range peerGroups {
		checkGroups[groupID] = struct{}{}
	}

	dnsManagementStatus := b.getPeerDNSManagementStatus(account, checkGroups)
	dnsConfig := &nbdns.Config{
		ServiceEnable: dnsManagementStatus,
	}

	if dnsManagementStatus {
		dnsConfig.NameServerGroups = b.getPeerNSGroups(account, peerID, checkGroups)
	}

	b.cache.peerDNS[peerID] = dnsConfig
}

func (b *NetworkMapBuilder) getPeerDNSManagementStatus(account *Account, checkGroups map[string]struct{}) bool {

	enabled := true
	for _, groupID := range account.DNSSettings.DisabledManagementGroups {
		_, found := checkGroups[groupID]
		if found {
			enabled = false
			break
		}
	}
	return enabled
}

func (b *NetworkMapBuilder) getPeerNSGroups(account *Account, peerID string, checkGroups map[string]struct{}) []*nbdns.NameServerGroup {
	var peerNSGroups []*nbdns.NameServerGroup

	for _, nsGroup := range account.NameServerGroups {
		if !nsGroup.Enabled {
			continue
		}
		for _, gID := range nsGroup.Groups {
			_, found := checkGroups[gID]
			if found {
				peer := b.cache.globalPeers[peerID]
				if !peerIsNameserver(peer, nsGroup) {
					peerNSGroups = append(peerNSGroups, nsGroup.Copy())
					break
				}
			}
		}
	}

	return peerNSGroups
}

func (b *NetworkMapBuilder) UpdateAccountPointer(account *Account) {
	b.account.Store(account)
}

func (b *NetworkMapBuilder) GetPeerNetworkMap(
	ctx context.Context, peerID string, peersCustomZone nbdns.CustomZone,
	validatedPeers map[string]struct{}, metrics *telemetry.AccountManagerMetrics,
) *NetworkMap {
	start := time.Now()
	account := b.account.Load()

	peer := account.GetPeer(peerID)
	if peer == nil {
		return &NetworkMap{Network: account.Network.Copy()}
	}

	b.cache.mu.RLock()
	defer b.cache.mu.RUnlock()

	aclView := b.cache.peerACLs[peerID]
	routesView := b.cache.peerRoutes[peerID]
	dnsConfig := b.cache.peerDNS[peerID]

	nm := b.assembleNetworkMap(account, peer, aclView, routesView, dnsConfig, peersCustomZone, validatedPeers)

	if metrics != nil {
		objectCount := int64(len(nm.Peers) + len(nm.OfflinePeers) + len(nm.Routes) + len(nm.FirewallRules) + len(nm.RoutesFirewallRules))
		metrics.CountNetworkMapObjects(objectCount)
		metrics.CountGetPeerNetworkMapDuration(time.Since(start))

		if objectCount > 5000 {
			log.WithContext(ctx).Tracef("account: %s has a total resource count of %d objects from cache",
				account.Id, objectCount)
		}
	}

	return nm
}

func (b *NetworkMapBuilder) assembleNetworkMap(
	account *Account, peer *nbpeer.Peer, aclView *PeerACLView, routesView *PeerRoutesView,
	dnsConfig *nbdns.Config, customZone nbdns.CustomZone, validatedPeers map[string]struct{},
) *NetworkMap {

	var peersToConnect []*nbpeer.Peer
	var expiredPeers []*nbpeer.Peer

	for _, peerID := range aclView.ConnectedPeerIDs {
		if _, ok := validatedPeers[peerID]; !ok {
			continue
		}

		peer := b.cache.globalPeers[peerID]
		if peer == nil {
			continue
		}

		expired, _ := peer.LoginExpired(account.Settings.PeerLoginExpiration)
		if account.Settings.PeerLoginExpirationEnabled && expired {
			expiredPeers = append(expiredPeers, peer)
		} else {
			peersToConnect = append(peersToConnect, peer)
		}
	}

	var routes []*route.Route
	allRouteIDs := slices.Concat(routesView.OwnRouteIDs, routesView.NetworkResourceIDs, routesView.InheritedRouteIDs)

	for _, routeID := range allRouteIDs {
		if route := b.cache.globalRoutes[routeID]; route != nil {
			routes = append(routes, route)
		}
	}

	var firewallRules []*FirewallRule
	for _, ruleID := range aclView.FirewallRuleIDs {
		if rule := b.cache.globalRules[ruleID]; rule != nil {
			firewallRules = append(firewallRules, rule)
		}
	}

	var routesFirewallRules []*RouteFirewallRule
	for _, ruleID := range routesView.RouteFirewallRuleIDs {
		if rule := b.cache.globalRouteRules[ruleID]; rule != nil {
			routesFirewallRules = append(routesFirewallRules, rule)
		}
	}

	finalDNSConfig := *dnsConfig
	if finalDNSConfig.ServiceEnable && customZone.Domain != "" {
		var zones []nbdns.CustomZone
		records := filterZoneRecordsForPeers(peer, customZone, peersToConnect)
		zones = append(zones, nbdns.CustomZone{
			Domain:  customZone.Domain,
			Records: records,
		})
		finalDNSConfig.CustomZones = zones
	}

	return &NetworkMap{
		Peers:               peersToConnect,
		Network:             account.Network.Copy(),
		Routes:              routes,
		DNSConfig:           finalDNSConfig,
		OfflinePeers:        expiredPeers,
		FirewallRules:       firewallRules,
		RoutesFirewallRules: routesFirewallRules,
	}
}

func (b *NetworkMapBuilder) generateFirewallRuleID(rule *FirewallRule) string {
	portRange := fmt.Sprintf("%d-%d", rule.PortRange.Start, rule.PortRange.End)
	return fmt.Sprintf("fw:%s:%s:%d:%s:%s:%s:%s",
		rule.PolicyID, rule.PeerIP, rule.Direction, rule.Protocol, rule.Action, rule.Port, portRange)
}

func (b *NetworkMapBuilder) generateRouteFirewallRuleID(rule *RouteFirewallRule) string {
	return fmt.Sprintf("route-fw:%s:%s:%s:%s:%s:%d",
		rule.RouteID, rule.Destination, rule.Action, strings.Join(rule.SourceRanges, ","), rule.Protocol, rule.Port)
}

func (b *NetworkMapBuilder) isPeerInGroups(groupIDs []string, peerGroups []string) bool {
	for _, groupID := range groupIDs {
		if slices.Contains(peerGroups, groupID) {
			return true
		}
	}
	return false
}

func (b *NetworkMapBuilder) isPeerRouter(account *Account, peerID string) bool {
	for _, r := range account.Routes {
		if !r.Enabled {
			continue
		}

		if r.PeerID == peerID {
			return true
		}

		if peer := b.cache.globalPeers[peerID]; peer != nil {
			if r.Peer == peer.Key && r.PeerID == "" {
				return true
			}
		}
	}

	routers := account.GetResourceRoutersMap()
	for _, networkRouters := range routers {
		if router, exists := networkRouters[peerID]; exists && router.Enabled {
			return true
		}
	}

	return false
}

type ViewDelta struct {
	AddedPeerIDs   []string
	RemovedPeerIDs []string
	AddedRuleIDs   []string
	RemovedRuleIDs []string
}

func (b *NetworkMapBuilder) OnPeerAddedIncremental(peerID string) error {
	account := b.account.Load()
	peer := account.GetPeer(peerID)
	if peer == nil {
		return fmt.Errorf("peer %s not found in account", peerID)
	}

	b.cache.mu.Lock()
	defer b.cache.mu.Unlock()

	log.Debugf("NetworkMapBuilder: Adding peer %s (IP: %s) to cache", peerID, peer.IP.String())

	b.validatedPeers[peerID] = struct{}{}

	b.cache.globalPeers[peerID] = peer

	peerGroups := b.updateIndexesForNewPeer(account, peerID)

	b.buildPeerACLView(account, peerID)
	b.buildPeerRoutesView(account, peerID)
	b.buildPeerDNSView(account, peerID)

	b.incrementalUpdateAffectedPeers(account, peerID, peerGroups)

	log.Debugf("NetworkMapBuilder: Added peer %s to cache", peerID)

	return nil
}

func (b *NetworkMapBuilder) updateIndexesForNewPeer(account *Account, peerID string) []string {
	peerGroups := make([]string, 0)

	for groupID, group := range account.Groups {
		if slices.Contains(group.Peers, peerID) {
			if !slices.Contains(b.cache.groupToPeers[groupID], peerID) {
				b.cache.groupToPeers[groupID] = append(b.cache.groupToPeers[groupID], peerID)
			}
			peerGroups = append(peerGroups, groupID)
		}
	}

	b.cache.peerToGroups[peerID] = peerGroups

	for _, r := range account.Routes {
		if !r.Enabled || b.cache.globalRoutes[r.ID] != nil {
			continue
		}
		for _, groupID := range r.PeerGroups {
			if !slices.Contains(b.cache.groupToRoutes[groupID], r) {
				b.cache.groupToRoutes[groupID] = append(b.cache.groupToRoutes[groupID], r)
			}
		}
		if r.Peer != "" {
			if peer, ok := b.cache.globalPeers[r.Peer]; ok {
				if !slices.Contains(b.cache.peerToRoutes[peer.ID], r) {
					b.cache.peerToRoutes[peer.ID] = append(b.cache.peerToRoutes[peer.ID], r)
				}
			}
		}
		b.cache.globalRoutes[r.ID] = r
	}

	return peerGroups
}

func (b *NetworkMapBuilder) incrementalUpdateAffectedPeers(account *Account, newPeerID string, peerGroups []string) {
	updates := b.calculateIncrementalUpdates(account, newPeerID, peerGroups)

	if b.isPeerRouter(account, newPeerID) {
		affectedByRoutes := b.findPeersAffectedByNewRouter(account, newPeerID, peerGroups)
		for affectedPeerID := range affectedByRoutes {
			if affectedPeerID == newPeerID {
				continue
			}
			if _, exists := updates[affectedPeerID]; !exists {
				updates[affectedPeerID] = &PeerUpdateDelta{
					PeerID:            affectedPeerID,
					RebuildRoutesView: true,
				}
			} else {
				updates[affectedPeerID].RebuildRoutesView = true
			}
		}
	}

	for affectedPeerID, delta := range updates {
		b.applyDeltaToPeer(account, affectedPeerID, delta)
	}
}

func (b *NetworkMapBuilder) findPeersAffectedByNewRouter(account *Account, newRouterID string, routerGroups []string) map[string]struct{} {
	affected := make(map[string]struct{})
	enabledRoutes, _ := b.getRoutingPeerRoutes(newRouterID)

	for _, route := range enabledRoutes {
		for _, distGroupID := range route.Groups {
			if peers := b.cache.groupToPeers[distGroupID]; peers != nil {
				for _, peerID := range peers {
					if peerID != newRouterID {
						affected[peerID] = struct{}{}
					}
				}
			}
		}

		for _, peerGroupID := range route.PeerGroups {
			if peers := b.cache.groupToPeers[peerGroupID]; peers != nil {
				for _, peerID := range peers {
					if peerID != newRouterID {
						affected[peerID] = struct{}{}
					}
				}
			}
		}
	}

	for _, route := range account.Routes {
		if !route.Enabled {
			continue
		}

		routerInPeerGroups := false
		for _, peerGroupID := range route.PeerGroups {
			if slices.Contains(routerGroups, peerGroupID) {
				routerInPeerGroups = true
				break
			}
		}

		if routerInPeerGroups {
			for _, distGroupID := range route.Groups {
				if peers := b.cache.groupToPeers[distGroupID]; peers != nil {
					for _, peerID := range peers {
						affected[peerID] = struct{}{}
					}
				}
			}
		}
	}

	return affected
}

func (b *NetworkMapBuilder) calculateIncrementalUpdates(account *Account, newPeerID string, peerGroups []string) map[string]*PeerUpdateDelta {
	updates := make(map[string]*PeerUpdateDelta)
	ctx := context.Background()

	groupAllLn := 0
	if allGroup, err := account.GetGroupAll(); err == nil {
		groupAllLn = len(allGroup.Peers) - 1
	}

	newPeer := b.cache.globalPeers[newPeerID]
	if newPeer == nil {
		return updates
	}

	for _, policy := range account.Policies {
		if !policy.Enabled {
			continue
		}

		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue
			}

			peerInSources := b.isPeerInGroups(rule.Sources, peerGroups)
			peerInDestinations := b.isPeerInGroups(rule.Destinations, peerGroups)

			if peerInSources {
				b.addUpdateForPeersInGroups(updates, rule.Destinations, newPeerID, rule, FirewallRuleDirectionIN, groupAllLn)
			}

			if peerInDestinations {
				b.addUpdateForPeersInGroups(updates, rule.Sources, newPeerID, rule, FirewallRuleDirectionOUT, groupAllLn)
			}

			if rule.Bidirectional {
				if peerInSources {
					b.addUpdateForPeersInGroups(updates, rule.Destinations, newPeerID, rule, FirewallRuleDirectionOUT, groupAllLn)
				}
				if peerInDestinations {
					b.addUpdateForPeersInGroups(updates, rule.Sources, newPeerID, rule, FirewallRuleDirectionIN, groupAllLn)
				}
			}
		}
	}

	b.calculateRouteFirewallUpdates(newPeerID, newPeer, peerGroups, updates)

	b.calculateNetworkResourceFirewallUpdates(ctx, account, newPeerID, newPeer, peerGroups, updates)

	return updates
}

func (b *NetworkMapBuilder) calculateRouteFirewallUpdates(
	newPeerID string, newPeer *nbpeer.Peer,
	peerGroups []string, updates map[string]*PeerUpdateDelta,
) {
	for peerID, routesView := range b.cache.peerRoutes {
		if peerID == newPeerID {
			continue
		}

		allRouteIDs := slices.Concat(routesView.OwnRouteIDs, routesView.NetworkResourceIDs)

		for _, routeID := range allRouteIDs {
			route := b.cache.globalRoutes[routeID]
			if route == nil || !route.Enabled {
				continue
			}

			if len(route.AccessControlGroups) == 0 {
				b.addRouteFirewallUpdate(updates, peerID, string(routeID), newPeer.IP.String())
				continue
			}

			for _, acg := range route.AccessControlGroups {
				if slices.Contains(peerGroups, acg) {
					b.addRouteFirewallUpdate(updates, peerID, string(routeID), newPeer.IP.String())
					break
				}
			}
		}
	}
}

func (b *NetworkMapBuilder) addRouteFirewallUpdate(
	updates map[string]*PeerUpdateDelta, peerID string,
	routeID string, sourceIP string,
) {
	delta := updates[peerID]
	if delta == nil {
		delta = &PeerUpdateDelta{
			PeerID:                   peerID,
			UpdateRouteFirewallRules: make([]*RouteFirewallRuleUpdate, 0),
		}
		updates[peerID] = delta
	}

	for _, existing := range delta.UpdateRouteFirewallRules {
		if existing.RuleID == routeID && existing.AddSourceIP == sourceIP {
			return
		}
	}

	delta.UpdateRouteFirewallRules = append(delta.UpdateRouteFirewallRules, &RouteFirewallRuleUpdate{
		RuleID:      routeID,
		AddSourceIP: sourceIP,
	})
}

func (b *NetworkMapBuilder) calculateNetworkResourceFirewallUpdates(
	ctx context.Context, account *Account, newPeerID string,
	newPeer *nbpeer.Peer, peerGroups []string, updates map[string]*PeerUpdateDelta,
) {
	for _, resource := range b.cache.globalResources {
		resourcePolicies := b.cache.resourcePolicies
		resourceRouters := b.cache.resourceRouters

		policies := resourcePolicies[resource.ID]
		peerHasAccess := false

		for _, policy := range policies {
			if !policy.Enabled {
				continue
			}

			sourceGroups := policy.SourceGroups()
			for _, sourceGroup := range sourceGroups {
				if slices.Contains(peerGroups, sourceGroup) {
					if account.validatePostureChecksOnPeer(ctx, policy.SourcePostureChecks, newPeerID) {
						peerHasAccess = true
						break
					}
				}
			}

			if peerHasAccess {
				break
			}
		}

		if !peerHasAccess {
			continue
		}

		networkRouters := resourceRouters[resource.NetworkID]
		for routerPeerID, router := range networkRouters {
			if !router.Enabled || routerPeerID == newPeerID {
				continue
			}

			delta := updates[routerPeerID]
			if delta == nil {
				delta = &PeerUpdateDelta{
					PeerID:                   routerPeerID,
					UpdateRouteFirewallRules: make([]*RouteFirewallRuleUpdate, 0),
				}
				updates[routerPeerID] = delta
			}

			resourceRouteID := fmt.Sprintf("network-resource-%s-%s", resource.ID, routerPeerID)

			delta.UpdateRouteFirewallRules = append(delta.UpdateRouteFirewallRules, &RouteFirewallRuleUpdate{
				RuleID:      resourceRouteID,
				AddSourceIP: newPeer.IP.String(),
			})
		}
	}
}

type PeerUpdateDelta struct {
	PeerID                   string
	AddConnectedPeer         string
	AddFirewallRules         []*FirewallRuleDelta
	AddRoutes                []route.ID
	UpdateRouteFirewallRules []*RouteFirewallRuleUpdate
	UpdateDNS                bool
	RebuildRoutesView        bool
}
type FirewallRuleDelta struct {
	Rule      *FirewallRule
	RuleID    string
	Direction int
}

type RouteFirewallRuleUpdate struct {
	RuleID      string
	AddSourceIP string
}

func (b *NetworkMapBuilder) addUpdateForPeersInGroups(
	updates map[string]*PeerUpdateDelta, groupIDs []string, newPeerID string,
	rule *PolicyRule, direction int, allGroupLn int,
) {
	for _, groupID := range groupIDs {
		peers := b.cache.groupToPeers[groupID]
		cnt := 0
		for _, peerID := range peers {
			if peerID == newPeerID {
				continue
			}
			if _, ok := b.validatedPeers[peerID]; !ok {
				continue
			}
			cnt++
		}
		all := false
		if allGroupLn > 0 && cnt == allGroupLn {
			all = true
		}
		newPeer := b.cache.globalPeers[newPeerID]
		fr := &FirewallRule{
			PolicyID:  rule.ID,
			PeerIP:    newPeer.IP.String(),
			Direction: direction,
			Action:    string(rule.Action),
			Protocol:  string(rule.Protocol),
		}
		for _, peerID := range peers {
			if peerID == newPeerID {
				continue
			}
			if _, ok := b.validatedPeers[peerID]; !ok {
				continue
			}
			delta := updates[peerID]
			if delta == nil {
				delta = &PeerUpdateDelta{
					PeerID:           peerID,
					AddConnectedPeer: newPeerID,
					AddFirewallRules: make([]*FirewallRuleDelta, 0),
				}
				updates[peerID] = delta
			}

			if all {
				fr.PeerIP = allPeers
			}

			if len(rule.Ports) > 0 || len(rule.PortRanges) > 0 {
				expandedRules := expandPortsAndRanges(*fr, rule, b.cache.globalPeers[peerID])
				for _, expandedRule := range expandedRules {
					ruleID := b.generateFirewallRuleID(expandedRule)
					delta.AddFirewallRules = append(delta.AddFirewallRules, &FirewallRuleDelta{
						Rule:      expandedRule,
						RuleID:    ruleID,
						Direction: direction,
					})
				}
			} else {
				ruleID := b.generateFirewallRuleID(fr)
				delta.AddFirewallRules = append(delta.AddFirewallRules, &FirewallRuleDelta{
					Rule:      fr,
					RuleID:    ruleID,
					Direction: direction,
				})
			}
		}
	}
}

func (b *NetworkMapBuilder) applyDeltaToPeer(account *Account, peerID string, delta *PeerUpdateDelta) {
	if delta.AddConnectedPeer != "" || len(delta.AddFirewallRules) > 0 {
		if aclView := b.cache.peerACLs[peerID]; aclView != nil {
			if delta.AddConnectedPeer != "" && !slices.Contains(aclView.ConnectedPeerIDs, delta.AddConnectedPeer) {
				aclView.ConnectedPeerIDs = append(aclView.ConnectedPeerIDs, delta.AddConnectedPeer)
			}

			for _, ruleDelta := range delta.AddFirewallRules {
				b.cache.globalRules[ruleDelta.RuleID] = ruleDelta.Rule

				if !slices.Contains(aclView.FirewallRuleIDs, ruleDelta.RuleID) {
					aclView.FirewallRuleIDs = append(aclView.FirewallRuleIDs, ruleDelta.RuleID)
				}
			}
		}
	}

	if delta.RebuildRoutesView {
		b.buildPeerRoutesView(account, peerID)
	} else if len(delta.UpdateRouteFirewallRules) > 0 {
		if routesView := b.cache.peerRoutes[peerID]; routesView != nil {
			b.updateRouteFirewallRules(routesView, delta.UpdateRouteFirewallRules)
		}
	}

	if delta.UpdateDNS {
		b.buildPeerDNSView(account, peerID)
	}
}

func (b *NetworkMapBuilder) updateRouteFirewallRules(routesView *PeerRoutesView, updates []*RouteFirewallRuleUpdate) {
	for _, update := range updates {
		updated := false

		for _, ruleID := range routesView.RouteFirewallRuleIDs {
			rule := b.cache.globalRouteRules[ruleID]
			if rule == nil {
				continue
			}

			if string(rule.RouteID) == update.RuleID {
				sourceIP := update.AddSourceIP

				if strings.Contains(sourceIP, ":") {
					sourceIP += "/128" // IPv6
				} else {
					sourceIP += "/32" // IPv4
				}

				if !slices.Contains(rule.SourceRanges, sourceIP) {
					rule.SourceRanges = append(rule.SourceRanges, sourceIP)
				}
				updated = true
				break
			}
		}

		if !updated {
			log.Debugf("Route firewall rule not found for route %s",
				update.RuleID)
		}
	}
}

func (b *NetworkMapBuilder) OnPeerDeleted(peerID string) error {
	b.cache.mu.Lock()
	defer b.cache.mu.Unlock()

	account := b.account.Load()

	deletedPeer := b.cache.globalPeers[peerID]
	if deletedPeer == nil {
		return fmt.Errorf("peer %s not found in cache", peerID)
	}

	deletedPeerKey := deletedPeer.Key
	peerGroups := b.cache.peerToGroups[peerID]
	peerIP := deletedPeer.IP.String()

	log.Debugf("NetworkMapBuilder: Deleting peer %s (IP: %s) from cache", peerID, peerIP)

	delete(b.validatedPeers, peerID)

	routesToDelete := []route.ID{}

	for routeID, r := range account.Routes {
		if r.Peer != deletedPeerKey && r.PeerID != peerID {
			continue
		}
		if len(r.PeerGroups) == 0 {
			routesToDelete = append(routesToDelete, routeID)
			continue
		}
		newPeerAssigned := false
		for _, groupID := range r.PeerGroups {
			candidatePeerIDs := b.cache.groupToPeers[groupID]
			for _, candidatePeerID := range candidatePeerIDs {
				if candidatePeerID == peerID {
					continue
				}
				if candidatePeer := b.cache.globalPeers[candidatePeerID]; candidatePeer != nil {
					r.Peer = candidatePeer.Key
					r.PeerID = candidatePeerID
					newPeerAssigned = true
					break
				}
			}
			if newPeerAssigned {
				break
			}
		}

		if !newPeerAssigned {
			routesToDelete = append(routesToDelete, routeID)
		}
	}

	for _, routeID := range routesToDelete {
		delete(account.Routes, routeID)
	}

	delete(b.cache.peerACLs, peerID)
	delete(b.cache.peerRoutes, peerID)
	delete(b.cache.peerDNS, peerID)

	delete(b.cache.globalPeers, peerID)

	for _, groupID := range peerGroups {
		if peers := b.cache.groupToPeers[groupID]; peers != nil {
			b.cache.groupToPeers[groupID] = slices.DeleteFunc(peers, func(id string) bool {
				return id == peerID
			})
		}
	}
	delete(b.cache.peerToGroups, peerID)

	affectedPeers := make(map[string]struct{})

	for _, r := range account.Routes {
		for _, groupID := range r.Groups {
			if peers := b.cache.groupToPeers[groupID]; peers != nil {
				for _, p := range peers {
					affectedPeers[p] = struct{}{}
				}
			}
		}

		for _, groupID := range r.PeerGroups {
			if peers := b.cache.groupToPeers[groupID]; peers != nil {
				for _, p := range peers {
					affectedPeers[p] = struct{}{}
				}
			}
		}
	}

	for affectedPeerID := range affectedPeers {
		if affectedPeerID == peerID {
			continue
		}
		b.buildPeerRoutesView(account, affectedPeerID)
	}

	peerDeletionUpdates := b.findPeersAffectedByDeletedPeerACL(peerID, peerIP)
	for affectedPeerID, updates := range peerDeletionUpdates {
		b.applyDeletionUpdates(affectedPeerID, updates)
	}

	b.cleanupUnusedRules()

	log.Debugf("NetworkMapBuilder: Deleted peer %s, affected %d other peers", peerID, len(affectedPeers))

	return nil
}

func (b *NetworkMapBuilder) findPeersAffectedByDeletedPeerACL(
	deletedPeerID string,
	peerIP string,
) map[string]*PeerDeletionUpdate {

	affected := make(map[string]*PeerDeletionUpdate)

	for peerID, aclView := range b.cache.peerACLs {
		if peerID == deletedPeerID {
			continue
		}

		if !slices.Contains(aclView.ConnectedPeerIDs, deletedPeerID) {
			continue
		}
		if affected[peerID] == nil {
			affected[peerID] = &PeerDeletionUpdate{
				RemovePeerID: deletedPeerID,
				PeerIP:       peerIP,
			}
		}

		for _, ruleID := range aclView.FirewallRuleIDs {
			if rule := b.cache.globalRules[ruleID]; rule != nil && rule.PeerIP == peerIP {
				affected[peerID].RemoveFirewallRuleIDs = append(
					affected[peerID].RemoveFirewallRuleIDs,
					ruleID,
				)
			}
		}
	}

	return affected
}

type PeerDeletionUpdate struct {
	RemovePeerID           string
	RemoveFirewallRuleIDs  []string
	RemoveRouteIDs         []route.ID
	RemoveFromSourceRanges bool
	PeerIP                 string
}

func (b *NetworkMapBuilder) applyDeletionUpdates(peerID string, updates *PeerDeletionUpdate) {
	if aclView := b.cache.peerACLs[peerID]; aclView != nil {
		aclView.ConnectedPeerIDs = slices.DeleteFunc(aclView.ConnectedPeerIDs, func(id string) bool {
			return id == updates.RemovePeerID
		})

		if len(updates.RemoveFirewallRuleIDs) > 0 {
			aclView.FirewallRuleIDs = slices.DeleteFunc(aclView.FirewallRuleIDs, func(ruleID string) bool {
				return slices.Contains(updates.RemoveFirewallRuleIDs, ruleID)
			})
		}
	}

	if routesView := b.cache.peerRoutes[peerID]; routesView != nil {
		if len(updates.RemoveRouteIDs) > 0 {
			routesView.NetworkResourceIDs = slices.DeleteFunc(routesView.NetworkResourceIDs, func(routeID route.ID) bool {
				return slices.Contains(updates.RemoveRouteIDs, routeID)
			})
		}

		if updates.RemoveFromSourceRanges {
			b.removeIPFromRouteFirewallRules(routesView, updates.PeerIP)
		}
	}
}

func (b *NetworkMapBuilder) removeIPFromRouteFirewallRules(routesView *PeerRoutesView, peerIP string) {
	sourceIPv4 := peerIP + "/32"
	sourceIPv6 := peerIP + "/128"

	rulesToRemove := []string{}

	for _, ruleID := range routesView.RouteFirewallRuleIDs {
		if rule := b.cache.globalRouteRules[ruleID]; rule != nil {
			rule.SourceRanges = slices.DeleteFunc(rule.SourceRanges, func(source string) bool {
				return source == sourceIPv4 || source == sourceIPv6 || source == peerIP
			})

			if len(rule.SourceRanges) == 0 {
				rulesToRemove = append(rulesToRemove, ruleID)
			}
		}
	}

	if len(rulesToRemove) > 0 {
		routesView.RouteFirewallRuleIDs = slices.DeleteFunc(routesView.RouteFirewallRuleIDs, func(ruleID string) bool {
			return slices.Contains(rulesToRemove, ruleID)
		})
	}
}

func (b *NetworkMapBuilder) cleanupUnusedRules() {
	usedFirewallRules := make(map[string]struct{})
	usedRouteRules := make(map[string]struct{})
	usedRoutes := make(map[route.ID]struct{})

	for _, aclView := range b.cache.peerACLs {
		for _, ruleID := range aclView.FirewallRuleIDs {
			usedFirewallRules[ruleID] = struct{}{}
		}
	}

	for _, routesView := range b.cache.peerRoutes {
		for _, ruleID := range routesView.RouteFirewallRuleIDs {
			usedRouteRules[ruleID] = struct{}{}
		}

		for _, routeID := range routesView.OwnRouteIDs {
			usedRoutes[routeID] = struct{}{}
		}
		for _, routeID := range routesView.NetworkResourceIDs {
			usedRoutes[routeID] = struct{}{}
		}
	}

	for ruleID := range b.cache.globalRules {
		if _, used := usedFirewallRules[ruleID]; !used {
			delete(b.cache.globalRules, ruleID)
		}
	}

	for ruleID := range b.cache.globalRouteRules {
		if _, used := usedRouteRules[ruleID]; !used {
			delete(b.cache.globalRouteRules, ruleID)
		}
	}

	for routeID := range b.cache.globalRoutes {
		if _, used := usedRoutes[routeID]; !used {
			delete(b.cache.globalRoutes, routeID)
		}
	}
}

func (b *NetworkMapBuilder) UpdatePeer(peer *nbpeer.Peer) {
	b.cache.mu.Lock()
	defer b.cache.mu.Unlock()
	peerStored, ok := b.cache.globalPeers[peer.ID]
	if !ok {
		return
	}
	*peerStored = *peer
}
