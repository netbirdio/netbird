package types

import (
	"context"
	"fmt"
	"slices"
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

type NetworkMapCache struct {
	globalRoutes     map[route.ID]*route.Route
	globalRules      map[string]*FirewallRule      //ruleId
	globalRouteRules map[string]*RouteFirewallRule //ruleId
	globalPeers      map[string]*nbpeer.Peer

	groupToPeers    map[string][]string
	peerToGroups    map[string][]string
	policyToRules   map[string][]*PolicyRule //policyId
	groupToPolicies map[string][]*Policy

	peerACLs   map[string]*PeerACLView
	peerRoutes map[string]*PeerRoutesView
	peerDNS    map[string]*nbdns.Config

	resourceRouters  map[string]map[string]*routerTypes.NetworkRouter
	resourcePolicies map[string][]*Policy

	mu sync.RWMutex
}

type PeerACLView struct {
	ConnectedPeerIDs []string
	FirewallRuleIDs  []string
}

type PeerRoutesView struct {
	OwnRouteIDs          []route.ID
	NetworkResourceIDs   []route.ID
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
			peerACLs:         make(map[string]*PeerACLView),
			peerRoutes:       make(map[string]*PeerRoutesView),
			peerDNS:          make(map[string]*nbdns.Config),
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

	for id, peer := range account.Peers {
		b.cache.globalPeers[id] = peer
	}

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
}

func (b *NetworkMapBuilder) buildPeerACLView(account *Account, peerID string) {
	ctx := context.Background()
	peer := account.GetPeer(peerID)
	if peer == nil {
		return
	}
	resourcePolicies := b.cache.resourcePolicies
	resourceRouters := b.cache.resourceRouters
	allPotentialPeers, firewallRules := account.GetPeerConnectionResources(ctx, peer, b.validatedPeers)

	isRouter, networkResourcesRoutes, sourcePeers := account.GetNetworkResourcesRoutesToSync(ctx, peerID, resourcePolicies, resourceRouters)

	var emptyExpiredPeers []*nbpeer.Peer
	finalAllPeers := account.addNetworksRoutingPeers(
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

func (b *NetworkMapBuilder) buildPeerRoutesView(account *Account, peerID string) {
	ctx := context.Background()
	peer := account.GetPeer(peerID)
	if peer == nil {
		return
	}
	resourcePolicies := b.cache.resourcePolicies
	resourceRouters := b.cache.resourceRouters

	view := &PeerRoutesView{
		OwnRouteIDs:          make([]route.ID, 0),
		NetworkResourceIDs:   make([]route.ID, 0),
		RouteFirewallRuleIDs: make([]string, 0),
	}

	enabledRoutes, disabledRoutes := account.getRoutingPeerRoutes(ctx, peerID)
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

			activeRoutes, _ := account.getRoutingPeerRoutes(ctx, aclPeerID)
			groupFilteredRoutes := account.filterRoutesByGroups(activeRoutes, peerGroupsMap)
			haFilteredRoutes := account.filterRoutesFromPeersOfSameHAGroup(groupFilteredRoutes, peerRoutesMembership)

			for _, inheritedRoute := range haFilteredRoutes {
				b.cache.globalRoutes[inheritedRoute.ID] = inheritedRoute
			}
		}
	}

	_, networkResourcesRoutes, _ := account.GetNetworkResourcesRoutesToSync(ctx, peerID, resourcePolicies, resourceRouters)

	for _, rt := range networkResourcesRoutes {
		view.NetworkResourceIDs = append(view.NetworkResourceIDs, rt.ID)
		b.cache.globalRoutes[rt.ID] = rt
	}

	routeFirewallRules := account.GetPeerRoutesFirewallRules(ctx, peerID, b.validatedPeers)
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

func (b *NetworkMapBuilder) buildPeerDNSView(account *Account, peerID string) {
	dnsManagementStatus := account.getPeerDNSManagementStatus(peerID)
	dnsConfig := &nbdns.Config{
		ServiceEnable: dnsManagementStatus,
	}

	if dnsManagementStatus {
		dnsConfig.NameServerGroups = getPeerNSGroups(account, peerID)
	}

	b.cache.peerDNS[peerID] = dnsConfig
}

func (b *NetworkMapBuilder) UpdateAccountPointer(account *Account) {
	b.account.Store(account)
}

func (b *NetworkMapBuilder) GetPeerNetworkMap(
	ctx context.Context,
	peerID string,
	peersCustomZone nbdns.CustomZone,
	validatedPeers map[string]struct{},
	metrics *telemetry.AccountManagerMetrics,
) *NetworkMap {
	start := time.Now()
	account := b.account.Load()

	peer := account.GetPeer(peerID)
	if peer == nil {
		return &NetworkMap{Network: account.Network.Copy()}
	}

	// if !maps.Equal(b.validatedPeers, validatedPeers) {
	// 	b.updateValidatedPeers(validatedPeers)
	// }

	b.cache.mu.RLock()
	defer b.cache.mu.RUnlock()

	aclView := b.cache.peerACLs[peerID]
	routesView := b.cache.peerRoutes[peerID]
	dnsConfig := b.cache.peerDNS[peerID]

	// if aclView == nil || routesView == nil || dnsConfig == nil {
	// 	// log.Warnf("NetworkMapBuilder: Cache miss for peer %s, falling back to original method", peerID)
	// 	// return account.GetPeerNetworkMap(ctx, peerID, peersCustomZone, validatedPeers, resourcePolicies, routers, metrics)
	// }

	nm := b.assembleNetworkMap(account, aclView, routesView, dnsConfig, peersCustomZone, validatedPeers)

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
	account *Account,
	aclView *PeerACLView,
	routesView *PeerRoutesView,
	dnsConfig *nbdns.Config,
	customZone nbdns.CustomZone,
	validatedPeers map[string]struct{},
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
	allRouteIDs := slices.Concat(routesView.OwnRouteIDs, routesView.NetworkResourceIDs)

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
		finalDNSConfig.CustomZones = append(finalDNSConfig.CustomZones, customZone)
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
		for _, peerGroupID := range peerGroups {
			if groupID == peerGroupID {
				return true
			}
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

		// ??
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

func (a *Account) GetNetworkResource(resourceID string) *resourceTypes.NetworkResource {
	for _, resource := range a.NetworkResources {
		if resource.ID == resourceID {
			return resource
		}
	}
	return nil
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

	b.validatedPeers[peerID] = struct{}{}

	b.cache.globalPeers[peerID] = peer

	peerGroups := b.updateGroupIndexesForNewPeer(account, peerID)

	b.buildPeerACLView(account, peerID)
	b.buildPeerRoutesView(account, peerID)
	b.buildPeerDNSView(account, peerID)

	b.incrementalUpdateAffectedPeers(account, peerID, peerGroups)

	return nil
}

func (b *NetworkMapBuilder) updateGroupIndexesForNewPeer(account *Account, peerID string) []string {
	peerGroups := make([]string, 0)

	for groupID, group := range account.Groups {
		for _, pid := range group.Peers {
			if pid == peerID {
				if !slices.Contains(b.cache.groupToPeers[groupID], peerID) {
					b.cache.groupToPeers[groupID] = append(b.cache.groupToPeers[groupID], peerID)
				}
				peerGroups = append(peerGroups, groupID)
				break
			}
		}
	}

	b.cache.peerToGroups[peerID] = peerGroups
	return peerGroups
}

func (b *NetworkMapBuilder) incrementalUpdateAffectedPeers(account *Account, newPeerID string, peerGroups []string) {
	ctx := context.Background()

	updates := b.calculateIncrementalUpdates(account, newPeerID, peerGroups)

	if b.isPeerRouter(account, newPeerID) {
		affectedByRoutes := b.findPeersAffectedByNewRouter(ctx, account, newPeerID, peerGroups)
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

func (b *NetworkMapBuilder) findPeersAffectedByNewRouter(ctx context.Context, account *Account, newRouterID string, routerGroups []string) map[string]struct{} {
	affected := make(map[string]struct{})

	enabledRoutes, _ := account.getRoutingPeerRoutes(ctx, newRouterID)

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
				b.addUpdateForPeersInGroups(updates, rule.Destinations, newPeerID, rule, FirewallRuleDirectionIN)
			}

			if peerInDestinations {
				b.addUpdateForPeersInGroups(updates, rule.Sources, newPeerID, rule, FirewallRuleDirectionOUT)
			}

			if rule.Bidirectional {
				if peerInSources {
					b.addUpdateForPeersInGroups(updates, rule.Destinations, newPeerID, rule, FirewallRuleDirectionOUT)
				}
				if peerInDestinations {
					b.addUpdateForPeersInGroups(updates, rule.Sources, newPeerID, rule, FirewallRuleDirectionIN)
				}
			}
		}
	}

	b.calculateRouteFirewallUpdates(newPeerID, newPeer, peerGroups, updates)

	b.calculateNetworkResourceFirewallUpdates(ctx, account, newPeerID, newPeer, peerGroups, updates)

	return updates
}

func (b *NetworkMapBuilder) calculateRouteFirewallUpdates(
	newPeerID string,
	newPeer *nbpeer.Peer,
	peerGroups []string,
	updates map[string]*PeerUpdateDelta,
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
	updates map[string]*PeerUpdateDelta,
	peerID string,
	routeID string,
	sourceIP string,
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
	ctx context.Context,
	account *Account,
	newPeerID string,
	newPeer *nbpeer.Peer,
	peerGroups []string,
	updates map[string]*PeerUpdateDelta,
) {
	for _, resource := range account.NetworkResources {
		if !resource.Enabled {
			continue
		}
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
	updates map[string]*PeerUpdateDelta,
	groupIDs []string,
	newPeerID string,
	rule *PolicyRule,
	direction int,
) {
	for _, groupID := range groupIDs {
		peers := b.cache.groupToPeers[groupID]
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

			newPeer := b.cache.globalPeers[newPeerID]
			if newPeer != nil {
				fr := &FirewallRule{
					PolicyID:  rule.ID,
					PeerIP:    newPeer.IP.String(),
					Direction: direction,
					Action:    string(rule.Action),
					Protocol:  string(rule.Protocol),
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
func (b *NetworkMapBuilder) updateRouteFirewallRules(
	routesView *PeerRoutesView,
	updates []*RouteFirewallRuleUpdate,
) {
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
		if r.Peer == deletedPeerKey || r.PeerID == peerID {
			if len(r.PeerGroups) > 0 {
				newPeerAssigned := false
				for _, groupID := range r.PeerGroups {
					if group := account.GetGroup(groupID); group != nil {
						for _, candidatePeerID := range group.Peers {
							if candidatePeerID != peerID {
								if candidatePeer := account.GetPeer(candidatePeerID); candidatePeer != nil {
									r.Peer = candidatePeer.Key
									r.PeerID = candidatePeerID
									newPeerAssigned = true
									break
								}
							}
						}
					}
					if newPeerAssigned {
						break
					}
				}

				if !newPeerAssigned {
					routesToDelete = append(routesToDelete, routeID)
				}
			} else {
				routesToDelete = append(routesToDelete, routeID)
			}
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

		if slices.Contains(aclView.ConnectedPeerIDs, deletedPeerID) {
			if affected[peerID] == nil {
				affected[peerID] = &PeerDeletionUpdate{
					RemovePeerID: deletedPeerID,
					PeerIP:       peerIP,
				}
			}

			for _, ruleID := range aclView.FirewallRuleIDs {
				if rule := b.cache.globalRules[ruleID]; rule != nil {
					if rule.PeerIP == peerIP {
						affected[peerID].RemoveFirewallRuleIDs = append(
							affected[peerID].RemoveFirewallRuleIDs,
							ruleID,
						)
					}
				}
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
