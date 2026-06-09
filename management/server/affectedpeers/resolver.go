// Package affectedpeers computes which peers' network maps a change touches, so
// only those peers are refreshed instead of the whole account.
//
// Two phases keep the dependency walk off the write transaction:
//   - Load: reads the needed collections. Call INSIDE the mutating tx (consistent,
//     and before a delete/removal severs the old state).
//   - Snapshot.Expand: in-memory walk, no store access. Run AFTER the tx commits.
//
// Enabled is never consulted: toggling it is itself an observable change.
package affectedpeers

import (
	"context"

	log "github.com/sirupsen/logrus"

	nbdns "github.com/netbirdio/netbird/dns"
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

// Snapshot is an in-memory view of the collections needed to expand a Change.
// Loaded in-tx, walked by Expand after commit. Only the collections the Change
// can touch are loaded; the rest stay nil (see Load).
type Snapshot struct {
	policies       []*types.Policy
	routes         []*route.Route
	nsGroups       []*nbdns.NameServerGroup
	dnsSettings    *types.DNSSettings
	routers        []*routerTypes.NetworkRouter
	resources      []*resourceTypes.NetworkResource
	services       []*rpservice.Service
	proxyByCluster map[string][]string
	groups         map[string]*types.Group
	groupPeers     map[string]map[string]struct{} // groupID -> member peer IDs
}

// Load reads the collections a Change requires, inside the caller's tx. It mirrors
// Expand's walker preconditions, loading only what the change can touch.
func Load(ctx context.Context, s store.Store, accountID string, c Change) (*Snapshot, error) {
	snap := &Snapshot{}
	if c.isEmpty() {
		return snap, nil
	}

	if err := snap.loadCollections(ctx, s, accountID, c); err != nil {
		return nil, err
	}
	if err := snap.loadGroupIndex(ctx, s, accountID); err != nil {
		return nil, err
	}

	return snap, nil
}

// loadCollections reads the policy/route/nameserver/dns/router/resource/proxy
// collections a Change can touch, gated to what the walk needs.
func (snap *Snapshot) loadCollections(ctx context.Context, s store.Store, accountID string, c Change) error {
	hasGroupOrPeerChange := len(c.ChangedGroupIDs) > 0 || len(c.ChangedPeerIDs) > 0 || len(c.Resources) > 0
	hasNetworkObject := len(c.Routers) > 0 || len(c.Resources) > 0 || len(c.Networks) > 0
	// the resource<->router bridge can fire for any of these
	needsRoutersResources := hasGroupOrPeerChange || len(c.PostureCheckIDs) > 0 || len(c.Policies) > 0 || hasNetworkObject

	if needsRoutersResources {
		if err := snap.loadPolicyRoutersResources(ctx, s, accountID); err != nil {
			return err
		}
	}
	if hasGroupOrPeerChange {
		if err := snap.loadRoutesAndProxy(ctx, s, accountID); err != nil {
			return err
		}
	}
	if len(c.ChangedGroupIDs) > 0 || len(c.ChangedPeerIDs) > 0 {
		if err := snap.loadDNS(ctx, s, accountID); err != nil {
			return err
		}
	}
	return nil
}

// loadPolicyRoutersResources loads the policies plus the routers and resources
// the resource<->router bridge walks.
func (snap *Snapshot) loadPolicyRoutersResources(ctx context.Context, s store.Store, accountID string) error {
	var err error
	if snap.policies, err = s.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID); err != nil {
		return err
	}
	if snap.routers, err = s.GetNetworkRoutersByAccountID(ctx, store.LockingStrengthNone, accountID); err != nil {
		return err
	}
	snap.resources, err = s.GetNetworkResourcesByAccountID(ctx, store.LockingStrengthNone, accountID)
	return err
}

// loadRoutesAndProxy loads the routes and the embedded-proxy services index.
func (snap *Snapshot) loadRoutesAndProxy(ctx context.Context, s store.Store, accountID string) error {
	var err error
	if snap.routes, err = s.GetAccountRoutes(ctx, store.LockingStrengthNone, accountID); err != nil {
		return err
	}
	return snap.loadProxyServices(ctx, s, accountID)
}

// loadDNS loads the nameserver groups and account DNS settings.
func (snap *Snapshot) loadDNS(ctx context.Context, s store.Store, accountID string) error {
	var err error
	if snap.nsGroups, err = s.GetAccountNameServerGroups(ctx, store.LockingStrengthNone, accountID); err != nil {
		return err
	}
	snap.dnsSettings, err = s.GetAccountDNSSettings(ctx, store.LockingStrengthNone, accountID)
	return err
}

// loadProxyServices loads the embedded-proxy cluster index, and the services only
// when the account actually has embedded proxy peers.
func (snap *Snapshot) loadProxyServices(ctx context.Context, s store.Store, accountID string) error {
	var err error
	if snap.proxyByCluster, err = s.GetEmbeddedProxyPeerIDsByCluster(ctx, accountID); err != nil {
		return err
	}
	if len(snap.proxyByCluster) == 0 {
		return nil
	}
	snap.services, err = s.GetAccountServices(ctx, store.LockingStrengthNone, accountID)
	return err
}

// loadGroupIndex loads all groups (for group.Resources) and builds the
// group->member-peers index. Always needed: the bridge resolves group.Resources
// and Expand maps groups to member peers.
func (snap *Snapshot) loadGroupIndex(ctx context.Context, s store.Store, accountID string) error {
	groups, err := s.GetAccountGroups(ctx, store.LockingStrengthNone, accountID)
	if err != nil {
		return err
	}
	snap.groups = make(map[string]*types.Group, len(groups))
	snap.groupPeers = make(map[string]map[string]struct{}, len(groups))
	for _, g := range groups {
		snap.groups[g.ID] = g
		members := make(map[string]struct{}, len(g.Peers))
		for _, pID := range g.Peers {
			members[pID] = struct{}{}
		}
		snap.groupPeers[g.ID] = members
	}
	return nil
}

// Change describes what changed in an account.
type Change struct {
	ChangedGroupIDs []string
	ChangedPeerIDs  []string
	Policies        []*types.Policy
	Routes          []*route.Route
	Routers         []*routerTypes.NetworkRouter
	Resources       []*resourceTypes.NetworkResource
	Networks        []*networkTypes.Network
	PostureCheckIDs []string

	// DistributionGroupIDs are groups whose members are directly affected, with no
	// dependency walk — the change distributes config to the groups' member peers
	// only (nameserver groups, DNS DisabledManagementGroups), not through the
	// policy/route reachability graph. Pass old∪new so both states refresh.
	DistributionGroupIDs []string

	// RemovedPeersByGroup: peers that left a group, keyed by that group. They are no
	// longer in the group's member index but still lose its reachability, so they are
	// folded in — but only when the group is linked (an unlinked group has no map
	// impact), matching how current members are handled.
	RemovedPeersByGroup map[string][]string
}

func (c Change) isEmpty() bool {
	return len(c.ChangedGroupIDs) == 0 &&
		len(c.ChangedPeerIDs) == 0 &&
		len(c.Policies) == 0 &&
		len(c.Routes) == 0 &&
		len(c.Routers) == 0 &&
		len(c.Resources) == 0 &&
		len(c.Networks) == 0 &&
		len(c.PostureCheckIDs) == 0 &&
		len(c.DistributionGroupIDs) == 0 &&
		len(c.RemovedPeersByGroup) == 0
}

// Expand returns the deduplicated affected peer IDs from the preloaded Snapshot,
// no store access. Run after the producing tx commits. Logs the full walk at
// trace level for diagnosing a miscalculation.
func (snap *Snapshot) Expand(ctx context.Context, accountID string, c Change) []string {
	if c.isEmpty() {
		return nil
	}
	r := newResolver(ctx, snap, accountID, c)
	log.WithContext(ctx).Tracef("affectedpeers expand start: account=%s changedGroups=%v changedPeers=%v policies=%d routes=%d routers=%d resources=%d networks=%d postureChecks=%v distributionGroups=%v",
		accountID, c.ChangedGroupIDs, c.ChangedPeerIDs, len(c.Policies), len(c.Routes), len(c.Routers), len(c.Resources), len(c.Networks), c.PostureCheckIDs, c.DistributionGroupIDs)
	r.walk()
	return r.expand()
}

// Collect returns the affected group and direct-peer IDs without expanding groups
// to members. Test-only introspection; use Resolve otherwise.
func Collect(ctx context.Context, s store.Store, accountID string, c Change) (groupIDs []string, directPeerIDs []string) {
	if c.isEmpty() {
		return nil, nil
	}
	snap, err := Load(ctx, s, accountID, c)
	if err != nil {
		log.WithContext(ctx).Errorf("failed to load snapshot for affected peers collect: %v", err)
		return nil, nil
	}
	r := newResolver(ctx, snap, accountID, c)
	r.walk()
	return setToSlice(r.groupSet), setToSlice(r.peerSet)
}

func newResolver(ctx context.Context, snap *Snapshot, accountID string, c Change) *resolver {
	r := &resolver{
		ctx:             ctx,
		snap:            snap,
		accountID:       accountID,
		change:          c,
		changedGroupSet: toSet(c.ChangedGroupIDs),
		changedPeerSet:  toSet(c.ChangedPeerIDs),
		groupSet:        make(map[string]struct{}),
		peerSet:         make(map[string]struct{}),
		networkIDs:      make(map[string]struct{}),
	}
	// Resolve each changed peer to its groups here so callers pass only ChangedPeerIDs.
	r.seedChangedGroupsFromPeers()
	r.matchedPolicies = append(r.matchedPolicies, c.Policies...)
	return r
}

// seedChangedGroupsFromPeers adds each changed peer's groups to changedGroupSet so
// the group-driven walkers fire for memberships, not just direct peer references.
func (r *resolver) seedChangedGroupsFromPeers() {
	if len(r.changedPeerSet) == 0 {
		return
	}
	for groupID, members := range r.snap.groupPeers {
		for pID := range r.changedPeerSet {
			if _, ok := members[pID]; ok {
				r.changedGroupSet[groupID] = struct{}{}
				break
			}
		}
	}
}

func (r *resolver) walk() {
	r.collectFromExplicitPolicies()
	r.collectFromExplicitRoutes(r.change.Routes)
	r.collectFromExplicitRouters(r.change.Routers)
	r.collectFromExplicitResources(r.change.Resources)
	r.collectFromExplicitNetworks(r.change.Networks)
	r.collectFromPostureChecks(r.change.PostureCheckIDs)

	// Distribution groups (nameserver/DNS) affect only their member peers: fold them
	// straight into groupSet so expand() maps them to members, without the policy/
	// route walk that changedGroupSet would trigger.
	addAll(r.groupSet, r.change.DistributionGroupIDs)

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
	snap      *Snapshot
	accountID string
	change    Change

	changedGroupSet map[string]struct{}
	changedPeerSet  map[string]struct{}

	groupSet map[string]struct{}
	peerSet  map[string]struct{}

	matchedPolicies []*types.Policy
	networkIDs      map[string]struct{}
}

func (r *resolver) policies() []*types.Policy { return r.snap.policies }

func (r *resolver) networkResources() []*resourceTypes.NetworkResource { return r.snap.resources }

func (r *resolver) networkRouters() []*routerTypes.NetworkRouter { return r.snap.routers }

// peerIDsForGroups maps a group set to its member peer IDs via the preloaded index.
func (r *resolver) peerIDsForGroups(groupSet map[string]struct{}) []string {
	seen := make(map[string]struct{})
	var ids []string
	for gID := range groupSet {
		for pID := range r.snap.groupPeers[gID] {
			if _, ok := seen[pID]; ok {
				continue
			}
			seen[pID] = struct{}{}
			ids = append(ids, pID)
		}
	}
	return ids
}

func (r *resolver) expand() []string {
	peerIDs := r.peerIDsForGroups(r.groupSet)

	log.WithContext(r.ctx).Tracef("affectedpeers expand: account=%s affectedGroups=%v -> %d group-member peers; direct peers=%v",
		r.accountID, setToSlice(r.groupSet), len(peerIDs), setToSlice(r.peerSet))

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

	// Fold in removed peers only when their group is linked (in groupSet).
	for groupID, removed := range r.change.RemovedPeersByGroup {
		if _, linked := r.groupSet[groupID]; !linked {
			continue
		}
		for _, id := range removed {
			if _, ok := seen[id]; !ok {
				peerIDs = append(peerIDs, id)
				seen[id] = struct{}{}
				log.WithContext(r.ctx).Tracef("affectedpeers expand: removed peer %s from linked group %s -> affected", id, groupID)
			}
		}
	}

	log.WithContext(r.ctx).Tracef("affectedpeers expand done: account=%s -> %d affected peers: %v", r.accountID, len(peerIDs), peerIDs)
	return peerIDs
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

// collectFromExplicitRouters folds changed routers' peers and marks their networks
// for the bridge. Passing the old router keeps a repointed router's previous peers
// affected without a post-commit read.
func (r *resolver) collectFromExplicitRouters(routers []*routerTypes.NetworkRouter) {
	for _, router := range routers {
		if router == nil {
			continue
		}
		log.WithContext(r.ctx).Tracef("collectFromExplicitRouters: changed router %s on network %s -> folding peerGroups=%v peer=%q and marking network for source bridge",
			router.ID, router.NetworkID, router.PeerGroups, router.Peer)
		addAll(r.groupSet, router.PeerGroups)
		if router.Peer != "" {
			r.peerSet[router.Peer] = struct{}{}
		}
		if router.NetworkID != "" {
			r.networkIDs[router.NetworkID] = struct{}{}
		}
	}
}

// collectFromExplicitResources marks changed resources' networks for the bridge and
// treats their group IDs as changed, so policies targeting the resource via a
// now-detached (old) group still refresh.
func (r *resolver) collectFromExplicitResources(resources []*resourceTypes.NetworkResource) {
	for _, resource := range resources {
		if resource == nil {
			continue
		}
		log.WithContext(r.ctx).Tracef("collectFromExplicitResources: changed resource %s on network %s -> marking network for bridge and treating groups %v as changed",
			resource.ID, resource.NetworkID, resource.GroupIDs)
		addAll(r.changedGroupSet, resource.GroupIDs)
		if resource.NetworkID != "" {
			r.networkIDs[resource.NetworkID] = struct{}{}
		}
	}
}

// collectFromExplicitNetworks marks changed networks for the bridge. A network has
// no groups/peers of its own.
func (r *resolver) collectFromExplicitNetworks(networks []*networkTypes.Network) {
	for _, network := range networks {
		if network == nil {
			continue
		}
		log.WithContext(r.ctx).Tracef("collectFromExplicitNetworks: changed network %s -> marking for bridge", network.ID)
		if network.ID != "" {
			r.networkIDs[network.ID] = struct{}{}
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
	for _, rt := range r.snap.routes {
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
	for _, ns := range r.snap.nsGroups {
		if anyInSet(ns.Groups, r.changedGroupSet) {
			log.WithContext(r.ctx).Tracef("collectFromNameServers: nameserver group %s references a changed group -> folding its groups %v", ns.ID, ns.Groups)
			addAll(r.groupSet, ns.Groups)
		}
	}
}

func (r *resolver) collectFromDNSSettings() {
	if len(r.changedGroupSet) == 0 || r.snap.dnsSettings == nil {
		return
	}
	for _, gID := range r.snap.dnsSettings.DisabledManagementGroups {
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
	if len(r.snap.proxyByCluster) == 0 || len(r.snap.services) == 0 {
		return
	}
	services, proxyByCluster := r.snap.services, r.snap.proxyByCluster

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

func (r *resolver) expandChangedPeersWithGroups() map[string]struct{} {
	if len(r.changedGroupSet) == 0 {
		return r.changedPeerSet
	}
	ids := r.peerIDsForGroups(r.changedGroupSet)
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

// collectResourceRouterBridge crosses between source peers and routing peers, which
// are reachable only via resource -> network -> router, not through the policy's own
// groups: source -> router (targeted resources' networks), then router -> source.
func (r *resolver) collectResourceRouterBridge() {
	r.bridgeSourceToRouters()
	r.bridgeRoutersToSources()
}

func (r *resolver) bridgeSourceToRouters() {
	resourceIDs := r.policyDestinationResourceIDs(r.matchedPolicies...)
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
	for gID := range destGroupSet {
		group := r.snap.groups[gID]
		if group == nil {
			continue
		}
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

// collectPolicyDestinations adds direct destination resource IDs to resourceIDs and
// returns the referenced destination group IDs.
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
	for gID := range groupIDs {
		group := r.snap.groups[gID]
		if group == nil {
			continue
		}
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
