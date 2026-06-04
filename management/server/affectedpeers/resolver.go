package affectedpeers

import (
	"context"

	log "github.com/sirupsen/logrus"

	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

// Change describes what changed in an account. The resolver never consults the
// Enabled flag of any object: toggling Enabled is itself an observable change.
type Change struct {
	ChangedGroupIDs []string
	ChangedPeerIDs  []string
	Policies        []*types.Policy
	Routes          []*route.Route
	PostureCheckIDs []string
	ResourceIDs     []string
	NetworkIDs      []string
}

func (c Change) isEmpty() bool {
	return len(c.ChangedGroupIDs) == 0 &&
		len(c.ChangedPeerIDs) == 0 &&
		len(c.Policies) == 0 &&
		len(c.Routes) == 0 &&
		len(c.PostureCheckIDs) == 0 &&
		len(c.ResourceIDs) == 0 &&
		len(c.NetworkIDs) == 0
}

// Resolve returns the deduplicated peer IDs whose network map may have changed by
// the given Change. Safe to call inside or after a transaction.
//
// At trace level it logs the full reasoning — which inputs drove which graph
// walks to which groups/peers, including the resource<->router bridge hops — so a
// miscalculation can be diagnosed from the logs alone.
func Resolve(ctx context.Context, s store.Store, accountID string, c Change) ([]string, error) {
	if c.isEmpty() {
		return nil, nil
	}
	r := newResolver(ctx, s, accountID, c)
	log.WithContext(ctx).Tracef("affectedpeers resolve start: account=%s changedGroups=%v changedPeers=%v policies=%d routes=%d postureChecks=%v resources=%v networks=%v",
		accountID, c.ChangedGroupIDs, c.ChangedPeerIDs, len(c.Policies), len(c.Routes), c.PostureCheckIDs, c.ResourceIDs, c.NetworkIDs)
	r.walk()
	return r.expand()
}

// Collect returns the affected group IDs and direct peer IDs without expanding
// groups to members. For tests asserting on the intermediate sets; use Resolve otherwise.
func Collect(ctx context.Context, s store.Store, accountID string, c Change) (groupIDs []string, directPeerIDs []string) {
	if c.isEmpty() {
		return nil, nil
	}
	r := newResolver(ctx, s, accountID, c)
	r.walk()
	return setToSlice(r.groupSet), setToSlice(r.peerSet)
}

func newResolver(ctx context.Context, s store.Store, accountID string, c Change) *resolver {
	r := &resolver{
		ctx:             ctx,
		store:           s,
		accountID:       accountID,
		change:          c,
		changedGroupSet: toSet(c.ChangedGroupIDs),
		changedPeerSet:  toSet(c.ChangedPeerIDs),
		groupSet:        make(map[string]struct{}),
		peerSet:         make(map[string]struct{}),
		resourceIDs:     toSet(c.ResourceIDs),
		networkIDs:      toSet(c.NetworkIDs),
	}
	r.matchedPolicies = append(r.matchedPolicies, c.Policies...)
	return r
}

func (r *resolver) walk() {
	r.collectFromExplicitPolicies()
	r.collectFromExplicitRoutes(r.change.Routes)
	r.collectFromPostureChecks(r.change.PostureCheckIDs)

	if len(r.changedGroupSet) > 0 || len(r.changedPeerSet) > 0 {
		r.collectFromPolicies()
		r.collectFromRoutes()
		r.collectFromNameServers()
		r.collectFromDNSSettings()
		r.collectFromNetworkRouters()
		r.collectFromProxyServices()
	}

	r.collectResourceRouterBridge()
}

type resolver struct {
	ctx       context.Context
	store     store.Store
	accountID string
	change    Change

	changedGroupSet map[string]struct{}
	changedPeerSet  map[string]struct{}

	groupSet map[string]struct{}
	peerSet  map[string]struct{}

	matchedPolicies []*types.Policy
	resourceIDs     map[string]struct{}
	networkIDs      map[string]struct{}

	// Memoized per-account collections: each is loaded from the store at most
	// once per Resolve and only when a walker actually needs it.
	cachedPolicies  []*types.Policy
	policiesLoaded  bool
	cachedResources []*resourceTypes.NetworkResource
	resourcesLoaded bool
	cachedRouters   []*routerTypes.NetworkRouter
	routersLoaded   bool
}

func (r *resolver) policies() []*types.Policy {
	if r.policiesLoaded {
		return r.cachedPolicies
	}
	r.policiesLoaded = true
	policies, err := r.store.GetAccountPolicies(r.ctx, store.LockingStrengthNone, r.accountID)
	if err != nil {
		log.WithContext(r.ctx).Errorf("failed to get policies for affected peers resolution: %v", err)
		return nil
	}
	r.cachedPolicies = policies
	return r.cachedPolicies
}

func (r *resolver) networkResources() []*resourceTypes.NetworkResource {
	if r.resourcesLoaded {
		return r.cachedResources
	}
	r.resourcesLoaded = true
	resources, err := r.store.GetNetworkResourcesByAccountID(r.ctx, store.LockingStrengthNone, r.accountID)
	if err != nil {
		log.WithContext(r.ctx).Errorf("failed to get network resources for affected peers resolution: %v", err)
		return nil
	}
	r.cachedResources = resources
	return r.cachedResources
}

func (r *resolver) networkRouters() []*routerTypes.NetworkRouter {
	if r.routersLoaded {
		return r.cachedRouters
	}
	r.routersLoaded = true
	routers, err := r.store.GetNetworkRoutersByAccountID(r.ctx, store.LockingStrengthNone, r.accountID)
	if err != nil {
		log.WithContext(r.ctx).Errorf("failed to get network routers for affected peers resolution: %v", err)
		return nil
	}
	r.cachedRouters = routers
	return r.cachedRouters
}

func (r *resolver) expand() ([]string, error) {
	groupIDs := setToSlice(r.groupSet)
	var peerIDs []string
	if len(groupIDs) > 0 {
		ids, err := r.store.GetPeerIDsByGroups(r.ctx, r.accountID, groupIDs)
		if err != nil {
			return nil, err
		}
		peerIDs = ids
	}

	log.WithContext(r.ctx).Tracef("affectedpeers resolve expand: account=%s affectedGroups=%v -> %d group-member peers; direct peers=%v",
		r.accountID, groupIDs, len(peerIDs), setToSlice(r.peerSet))

	seen := make(map[string]struct{}, len(peerIDs))
	for _, id := range peerIDs {
		seen[id] = struct{}{}
	}
	for id := range r.peerSet {
		if _, ok := seen[id]; !ok {
			peerIDs = append(peerIDs, id)
			seen[id] = struct{}{}
		}
	}

	log.WithContext(r.ctx).Tracef("affectedpeers resolve done: account=%s -> %d affected peers: %v", r.accountID, len(peerIDs), peerIDs)
	return peerIDs, nil
}

func (r *resolver) collectFromExplicitPolicies() {
	for _, policy := range r.matchedPolicies {
		if policy == nil {
			continue
		}
		log.WithContext(r.ctx).Tracef("collectFromExplicitPolicies: changed policy %s (%s) -> folding rule groups %v + direct peers",
			policy.ID, policy.Name, policy.RuleGroups())
		addAll(r.groupSet, policy.RuleGroups())
		collectPolicyDirectPeers(policy, r.peerSet)
	}
}

func (r *resolver) collectFromExplicitRoutes(routes []*route.Route) {
	for _, rt := range routes {
		if rt == nil {
			continue
		}
		log.WithContext(r.ctx).Tracef("collectFromExplicitRoutes: changed route %s -> folding groups=%v peerGroups=%v accessControlGroups=%v peer=%q",
			rt.ID, rt.Groups, rt.PeerGroups, rt.AccessControlGroups, rt.Peer)
		addAll(r.groupSet, rt.Groups, rt.PeerGroups, rt.AccessControlGroups)
		if rt.Peer != "" {
			r.peerSet[rt.Peer] = struct{}{}
		}
	}
}

func (r *resolver) collectFromPostureChecks(postureCheckIDs []string) {
	if len(postureCheckIDs) == 0 {
		return
	}
	ids := toSet(postureCheckIDs)
	for _, policy := range r.policies() {
		if !policyReferencesPostureChecks(policy, ids) {
			continue
		}
		log.WithContext(r.ctx).Tracef("collectFromPostureChecks: policy %s (%s) references changed posture checks %v -> folding rule groups %v + direct peers",
			policy.ID, policy.Name, postureCheckIDs, policy.RuleGroups())
		addAll(r.groupSet, policy.RuleGroups())
		collectPolicyDirectPeers(policy, r.peerSet)
		r.matchedPolicies = append(r.matchedPolicies, policy)
	}
}

func (r *resolver) collectFromPolicies() {
	for _, policy := range r.policies() {
		matchedByGroup := policyReferencesGroups(policy, r.changedGroupSet)
		matchedByPeer := len(r.changedPeerSet) > 0 && policyReferencesDirectPeers(policy, r.changedPeerSet)
		if !matchedByGroup && !matchedByPeer {
			continue
		}
		log.WithContext(r.ctx).Tracef("collectFromPolicies: policy %s (%s) matched (byGroup=%t byPeer=%t) -> folding rule groups %v + direct peers",
			policy.ID, policy.Name, matchedByGroup, matchedByPeer, policy.RuleGroups())
		addAll(r.groupSet, policy.RuleGroups())
		collectPolicyDirectPeers(policy, r.peerSet)
		r.matchedPolicies = append(r.matchedPolicies, policy)
	}
}

func (r *resolver) collectFromRoutes() {
	routes, err := r.store.GetAccountRoutes(r.ctx, store.LockingStrengthNone, r.accountID)
	if err != nil {
		log.WithContext(r.ctx).Errorf("failed to get routes for affected peers resolution: %v", err)
		return
	}
	for _, rt := range routes {
		matchedByGroup := anyInSet(rt.Groups, r.changedGroupSet) || anyInSet(rt.PeerGroups, r.changedGroupSet) || anyInSet(rt.AccessControlGroups, r.changedGroupSet)
		matchedByPeer := rt.Peer != "" && len(r.changedPeerSet) > 0 && isInSet(rt.Peer, r.changedPeerSet)
		if !matchedByGroup && !matchedByPeer {
			continue
		}
		log.WithContext(r.ctx).Tracef("collectFromRoutes: route %s matched (byGroup=%t byPeer=%t) -> folding groups=%v peerGroups=%v accessControlGroups=%v peer=%q",
			rt.ID, matchedByGroup, matchedByPeer, rt.Groups, rt.PeerGroups, rt.AccessControlGroups, rt.Peer)
		addAll(r.groupSet, rt.Groups, rt.PeerGroups, rt.AccessControlGroups)
		if rt.Peer != "" {
			r.peerSet[rt.Peer] = struct{}{}
		}
	}
}

func (r *resolver) collectFromNameServers() {
	if len(r.changedGroupSet) == 0 {
		return
	}
	nsGroups, err := r.store.GetAccountNameServerGroups(r.ctx, store.LockingStrengthNone, r.accountID)
	if err != nil {
		log.WithContext(r.ctx).Errorf("failed to get nameserver groups for affected peers resolution: %v", err)
		return
	}
	for _, ns := range nsGroups {
		if anyInSet(ns.Groups, r.changedGroupSet) {
			log.WithContext(r.ctx).Tracef("collectFromNameServers: nameserver group %s references a changed group -> folding its groups %v", ns.ID, ns.Groups)
			addAll(r.groupSet, ns.Groups)
		}
	}
}

func (r *resolver) collectFromDNSSettings() {
	if len(r.changedGroupSet) == 0 {
		return
	}
	dnsSettings, err := r.store.GetAccountDNSSettings(r.ctx, store.LockingStrengthNone, r.accountID)
	if err != nil {
		log.WithContext(r.ctx).Errorf("failed to get DNS settings for affected peers resolution: %v", err)
		return
	}
	for _, gID := range dnsSettings.DisabledManagementGroups {
		if _, ok := r.changedGroupSet[gID]; ok {
			log.WithContext(r.ctx).Tracef("collectFromDNSSettings: changed group %s is in DisabledManagementGroups -> folding it", gID)
			r.groupSet[gID] = struct{}{}
		}
	}
}

func (r *resolver) collectFromNetworkRouters() {
	for _, router := range r.networkRouters() {
		matchedByGroup := anyInSet(router.PeerGroups, r.changedGroupSet)
		matchedByPeer := router.Peer != "" && len(r.changedPeerSet) > 0 && isInSet(router.Peer, r.changedPeerSet)
		if !matchedByGroup && !matchedByPeer {
			continue
		}
		log.WithContext(r.ctx).Tracef("collectFromNetworkRouters: router %s on network %s matched (byGroup=%t byPeer=%t) -> folding peerGroups=%v peer=%q and marking network for source bridge",
			router.ID, router.NetworkID, matchedByGroup, matchedByPeer, router.PeerGroups, router.Peer)
		addAll(r.groupSet, router.PeerGroups)
		if router.Peer != "" {
			r.peerSet[router.Peer] = struct{}{}
		}
		r.networkIDs[router.NetworkID] = struct{}{}
	}
}

func (r *resolver) collectFromProxyServices() {
	services, proxyByCluster, ok := r.loadProxyServiceContext()
	if !ok {
		return
	}

	expanded := r.expandChangedPeersWithGroups()

	for _, svc := range services {
		if svc == nil {
			continue
		}
		proxyPeers := proxyByCluster[svc.ProxyCluster]
		if len(proxyPeers) == 0 {
			continue
		}
		matchedByPeer := serviceMatchesChangedPeers(svc, proxyPeers, expanded)
		matchedByAccessGroup := anyInSet(svc.AccessGroups, r.changedGroupSet)
		if !matchedByPeer && !matchedByAccessGroup {
			continue
		}
		log.WithContext(r.ctx).Tracef("collectFromProxyServices: service %s (cluster=%s) matched (byProxyOrTargetPeer=%t byAccessGroup=%t) -> folding %d proxy peers, peer targets and access groups %v",
			svc.ID, svc.ProxyCluster, matchedByPeer, matchedByAccessGroup, len(proxyPeers), svc.AccessGroups)
		for _, pid := range proxyPeers {
			r.peerSet[pid] = struct{}{}
		}
		for _, target := range svc.Targets {
			if target.TargetType == rpservice.TargetTypePeer && target.TargetId != "" {
				r.peerSet[target.TargetId] = struct{}{}
			}
		}
		addAll(r.groupSet, svc.AccessGroups)
	}
}

func (r *resolver) loadProxyServiceContext() ([]*rpservice.Service, map[string][]string, bool) {
	// Embedded proxy peers are the prerequisite for any synthesized proxy policy.
	// Probe that first (a narrow, indexed lookup) and skip the services table load
	// entirely when the account has no embedded proxy peers.
	proxyByCluster, err := r.store.GetEmbeddedProxyPeerIDsByCluster(r.ctx, r.accountID)
	if err != nil {
		log.WithContext(r.ctx).Errorf("failed to get embedded proxy peers for affected peers resolution: %v", err)
		return nil, nil, false
	}
	if len(proxyByCluster) == 0 {
		return nil, nil, false
	}
	services, err := r.store.GetAccountServices(r.ctx, store.LockingStrengthNone, r.accountID)
	if err != nil {
		log.WithContext(r.ctx).Errorf("failed to get services for affected peers resolution: %v", err)
		return nil, nil, false
	}
	if len(services) == 0 {
		return nil, nil, false
	}
	return services, proxyByCluster, true
}

func (r *resolver) expandChangedPeersWithGroups() map[string]struct{} {
	if len(r.changedGroupSet) == 0 {
		return r.changedPeerSet
	}
	ids, err := r.store.GetPeerIDsByGroups(r.ctx, r.accountID, setToSlice(r.changedGroupSet))
	if err != nil {
		log.WithContext(r.ctx).Errorf("failed to expand changed groups to peers for service resolution: %v", err)
		return r.changedPeerSet
	}
	if len(ids) == 0 {
		return r.changedPeerSet
	}
	merged := make(map[string]struct{}, len(r.changedPeerSet)+len(ids))
	for id := range r.changedPeerSet {
		merged[id] = struct{}{}
	}
	for _, id := range ids {
		merged[id] = struct{}{}
	}
	return merged
}

// collectResourceRouterBridge folds in the routing peers serving the resources
// targeted by matched/explicit policies (source -> router), and the source peers
// of policies serving resources on the affected networks (router -> source). The
// routing peer is reachable only through resource -> network -> router, never
// through the policy's own groups, so it must be collected here.
func (r *resolver) collectResourceRouterBridge() {
	r.bridgeSourceToRouters()
	r.bridgeRoutersToSources()
}

func (r *resolver) bridgeSourceToRouters() {
	resourceIDs := r.policyDestinationResourceIDs(r.matchedPolicies...)
	for id := range r.resourceIDs {
		resourceIDs[id] = struct{}{}
	}
	if len(resourceIDs) == 0 {
		return
	}

	networkIDs := r.resourceNetworkIDs(resourceIDs)
	log.WithContext(r.ctx).Tracef("bridgeSourceToRouters: targeted resources %v -> networks %v (their routers become affected via the router->source pass)",
		setToSlice(resourceIDs), setToSlice(networkIDs))
	for id := range networkIDs {
		r.networkIDs[id] = struct{}{}
	}
}

func (r *resolver) bridgeRoutersToSources() {
	if len(r.networkIDs) == 0 {
		return
	}

	log.WithContext(r.ctx).Tracef("bridgeRoutersToSources: affected networks %v -> folding their routing peers and the source peers of policies targeting their resources",
		setToSlice(r.networkIDs))

	r.foldRoutersOnNetworks(r.networkIDs)

	resourceIDs := make(map[string]struct{})
	for _, resource := range r.networkResources() {
		if _, ok := r.networkIDs[resource.NetworkID]; ok {
			resourceIDs[resource.ID] = struct{}{}
		}
	}
	if len(resourceIDs) == 0 {
		return
	}

	for _, policy := range r.policies() {
		if r.policyTargetsResources(policy, resourceIDs) {
			log.WithContext(r.ctx).Tracef("bridgeRoutersToSources: policy %s (%s) targets an affected-network resource -> folding its source groups/peers", policy.ID, policy.Name)
			collectPolicySources(policy, r.groupSet, r.peerSet)
		}
	}
}

func (r *resolver) foldRoutersOnNetworks(networkIDs map[string]struct{}) {
	for _, router := range r.networkRouters() {
		if _, ok := networkIDs[router.NetworkID]; !ok {
			continue
		}
		log.WithContext(r.ctx).Tracef("bridgeRoutersToSources: router %s serves affected network %s -> folding peerGroups=%v peer=%q",
			router.ID, router.NetworkID, router.PeerGroups, router.Peer)
		addAll(r.groupSet, router.PeerGroups)
		if router.Peer != "" {
			r.peerSet[router.Peer] = struct{}{}
		}
	}
}

func (r *resolver) resourceNetworkIDs(resourceIDs map[string]struct{}) map[string]struct{} {
	networkIDs := make(map[string]struct{})
	for _, resource := range r.networkResources() {
		if _, ok := resourceIDs[resource.ID]; ok {
			networkIDs[resource.NetworkID] = struct{}{}
		}
	}
	return networkIDs
}

func (r *resolver) policyTargetsResources(policy *types.Policy, resourceIDs map[string]struct{}) bool {
	if policy == nil {
		return false
	}
	destGroupSet := make(map[string]struct{})
	for _, rule := range policy.Rules {
		if rule.DestinationResource.Type != types.ResourceTypePeer && isInSet(rule.DestinationResource.ID, resourceIDs) {
			return true
		}
		for _, gID := range rule.Destinations {
			destGroupSet[gID] = struct{}{}
		}
	}
	if len(destGroupSet) == 0 {
		return false
	}
	groups, err := r.store.GetGroupsByIDs(r.ctx, store.LockingStrengthNone, r.accountID, setToSlice(destGroupSet))
	if err != nil {
		log.WithContext(r.ctx).Errorf("failed to get destination groups for router policy bridge: %v", err)
		return false
	}
	for _, group := range groups {
		for _, res := range group.Resources {
			if isInSet(res.ID, resourceIDs) {
				return true
			}
		}
	}
	return false
}

func (r *resolver) policyDestinationResourceIDs(policies ...*types.Policy) map[string]struct{} {
	resourceIDs := make(map[string]struct{})
	destGroupSet := collectPolicyDestinations(resourceIDs, policies...)
	r.addGroupResourceIDs(destGroupSet, resourceIDs)
	return resourceIDs
}

// collectPolicyDestinations adds each rule's direct destination resource IDs to
// resourceIDs and returns the set of destination group IDs referenced.
func collectPolicyDestinations(resourceIDs map[string]struct{}, policies ...*types.Policy) map[string]struct{} {
	destGroupSet := make(map[string]struct{})
	for _, policy := range policies {
		if policy == nil {
			continue
		}
		for _, rule := range policy.Rules {
			addAll(destGroupSet, rule.Destinations)
			if rule.DestinationResource.Type != types.ResourceTypePeer && rule.DestinationResource.ID != "" {
				resourceIDs[rule.DestinationResource.ID] = struct{}{}
			}
		}
	}
	return destGroupSet
}

// addGroupResourceIDs folds the resource IDs of the given groups into resourceIDs.
func (r *resolver) addGroupResourceIDs(groupIDs map[string]struct{}, resourceIDs map[string]struct{}) {
	if len(groupIDs) == 0 {
		return
	}
	groups, err := r.store.GetGroupsByIDs(r.ctx, store.LockingStrengthNone, r.accountID, setToSlice(groupIDs))
	if err != nil {
		log.WithContext(r.ctx).Errorf("failed to get destination groups for resource router bridge: %v", err)
		return
	}
	for _, group := range groups {
		for _, res := range group.Resources {
			if res.ID != "" {
				resourceIDs[res.ID] = struct{}{}
			}
		}
	}
}

func collectPolicyDirectPeers(policy *types.Policy, peerSet map[string]struct{}) {
	for _, rule := range policy.Rules {
		if rule.SourceResource.Type == types.ResourceTypePeer && rule.SourceResource.ID != "" {
			peerSet[rule.SourceResource.ID] = struct{}{}
		}
		if rule.DestinationResource.Type == types.ResourceTypePeer && rule.DestinationResource.ID != "" {
			peerSet[rule.DestinationResource.ID] = struct{}{}
		}
	}
}

func collectPolicySources(policy *types.Policy, groupSet, peerSet map[string]struct{}) {
	for _, rule := range policy.Rules {
		addAll(groupSet, rule.Sources)
		if rule.SourceResource.Type == types.ResourceTypePeer && rule.SourceResource.ID != "" {
			peerSet[rule.SourceResource.ID] = struct{}{}
		}
	}
}

func policyReferencesGroups(policy *types.Policy, groupSet map[string]struct{}) bool {
	for _, rule := range policy.Rules {
		if anyInSet(rule.Sources, groupSet) || anyInSet(rule.Destinations, groupSet) {
			return true
		}
	}
	return false
}

func policyReferencesDirectPeers(policy *types.Policy, changedSet map[string]struct{}) bool {
	for _, rule := range policy.Rules {
		if isDirectPeerInSet(rule.SourceResource, changedSet) || isDirectPeerInSet(rule.DestinationResource, changedSet) {
			return true
		}
	}
	return false
}

func policyReferencesPostureChecks(policy *types.Policy, ids map[string]struct{}) bool {
	for _, id := range policy.SourcePostureChecks {
		if _, ok := ids[id]; ok {
			return true
		}
	}
	return false
}

func isDirectPeerInSet(res types.Resource, set map[string]struct{}) bool {
	if res.Type != types.ResourceTypePeer || res.ID == "" {
		return false
	}
	_, ok := set[res.ID]
	return ok
}

func serviceMatchesChangedPeers(svc *rpservice.Service, proxyPeers []string, changedPeers map[string]struct{}) bool {
	for _, pid := range proxyPeers {
		if _, ok := changedPeers[pid]; ok {
			return true
		}
	}
	for _, target := range svc.Targets {
		if target.TargetType != rpservice.TargetTypePeer || target.TargetId == "" {
			continue
		}
		if _, ok := changedPeers[target.TargetId]; ok {
			return true
		}
	}
	return false
}

func anyInSet(ids []string, set map[string]struct{}) bool {
	for _, id := range ids {
		if _, ok := set[id]; ok {
			return true
		}
	}
	return false
}

func isInSet(id string, set map[string]struct{}) bool {
	_, ok := set[id]
	return ok
}

func addAll(set map[string]struct{}, slices ...[]string) {
	for _, s := range slices {
		for _, id := range s {
			set[id] = struct{}{}
		}
	}
}

func toSet(ids []string) map[string]struct{} {
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		set[id] = struct{}{}
	}
	return set
}

func setToSlice(set map[string]struct{}) []string {
	s := make([]string, 0, len(set))
	for id := range set {
		s = append(s, id)
	}
	return s
}
