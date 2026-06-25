// Package affectedpeers computes which peers' network maps a change touches, so
// only those peers are refreshed instead of the whole account.
//
// Two phases keep the dependency walk off the write transaction:
//   - Load: reads the needed collections. Call INSIDE the mutating tx (consistent,
//     and before a delete/removal severs the old state).
//   - Snapshot.Expand: in-memory walk, no store access. Run AFTER the tx commits.
//
// Enabled handling differs by source. Disabled objects in the SNAPSHOT (existing
// account policies/resources/routers/routes/proxy services and their rules/targets)
// route to nobody and are skipped — they cannot affect any peer's map. Objects in
// the CHANGE itself are processed regardless of Enabled, so disabling one still
// refreshes the peers that lose access (the toggle is the observable change, and the
// update carries the old∪new state).
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
	// LinkGroups drive the same policy/route/dns walk as a changed group or peer.
	hasGroupOrPeerChange := len(c.ChangedGroupIDs) > 0 || len(c.ChangedPeerIDs) > 0 || len(c.LinkGroups) > 0 || len(c.Resources) > 0
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
	if len(c.ChangedGroupIDs) > 0 || len(c.ChangedPeerIDs) > 0 || len(c.LinkGroups) > 0 {
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

	// OutputPeerIDs are peers folded straight into the result without seeding their
	// group memberships into the walk. Use for the peer whose group membership changed:
	// the peer itself must refresh, but its OTHER groups did not change, so they must
	// not be walked. Contrast ChangedPeerIDs, which seeds ALL of the peer's groups
	// (correct when the peer's own attributes changed, e.g. IP/status).
	OutputPeerIDs []string

	// LinkGroups are groups used ONLY to match policies/routes/routers and walk to the
	// OPPOSITE side — they are never expanded to their own members. Use this when a
	// peer's group membership changed: pass the peer in ChangedPeerIDs and its
	// group(s) here. The opposite side of the policies the group participates in
	// refreshes, but the group's other members (siblings) do not — nothing changed for
	// them. For an intra-group policy (A→A) the opposite side IS the group, so its
	// members still refresh via the opposite-side fold, exactly when they genuinely
	// gain/lose the changed peer. Unlike ChangedGroupIDs, a LinkGroup is not added to
	// the output, so a one-sided membership change never wakes the whole group.
	LinkGroups []string
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
		len(c.RemovedPeersByGroup) == 0 &&
		len(c.LinkGroups) == 0 &&
		len(c.OutputPeerIDs) == 0
}

// Expand returns the deduplicated affected peer IDs from the preloaded Snapshot,
// no store access. Run after the producing tx commits. Logs the full walk at
// trace level for diagnosing a miscalculation.
func (snap *Snapshot) Expand(ctx context.Context, accountID string, c Change) []string {
	if c.isEmpty() {
		return nil
	}
	r := newResolver(ctx, snap, accountID, c)
	log.WithContext(ctx).Tracef("affectedpeers expand start: account=%s changedGroups=%v changedPeers=%v linkGroups=%v policies=%d routes=%d routers=%d resources=%d networks=%d postureChecks=%v distributionGroups=%v",
		accountID, c.ChangedGroupIDs, c.ChangedPeerIDs, c.LinkGroups, len(c.Policies), len(c.Routes), len(c.Routers), len(c.Resources), len(c.Networks), c.PostureCheckIDs, c.DistributionGroupIDs)
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
	return setToSlice(r.affectedGroups), setToSlice(r.affectedPeers)
}

func newResolver(ctx context.Context, snap *Snapshot, accountID string, c Change) *resolver {
	r := &resolver{
		ctx:            ctx,
		snap:           snap,
		accountID:      accountID,
		change:         c,
		linkGroups:     toSet(c.ChangedGroupIDs),
		outputGroups:   toSet(c.ChangedGroupIDs),
		changedPeers:   toSet(c.ChangedPeerIDs),
		affectedGroups: make(map[string]struct{}),
		affectedPeers:  make(map[string]struct{}),
	}
	// LinkGroups match policies/routes to find the opposite side but are NOT output:
	// they go into linkGroups only, never outputGroups, so their members never fold in.
	addAll(r.linkGroups, c.LinkGroups)
	// Resolve each changed peer to its groups here so callers pass only ChangedPeerIDs.
	r.seedChangedGroupsFromPeers()
	return r
}

// seedChangedGroupsFromPeers adds each changed peer's groups to linkGroups so
// the group-driven walkers fire for memberships, not just direct peer references.
// These seeded groups are for MATCHING only — folding the changed entity's own
// side is gated on outputGroups (the caller-reported groups), so a seeded group
// never folds its whole membership; only the changed peer itself folds in.
func (r *resolver) seedChangedGroupsFromPeers() {
	if len(r.changedPeers) == 0 {
		return
	}
	for groupID, members := range r.snap.groupPeers {
		for pID := range r.changedPeers {
			if _, ok := members[pID]; ok {
				r.linkGroups[groupID] = struct{}{}
				break
			}
		}
	}
}

// policySide selects which side of a policy rule to walk.
type policySide int

const (
	sideSource policySide = iota
	sideDestination
)

func (s policySide) opposite() policySide {
	if s == sideSource {
		return sideDestination
	}
	return sideSource
}

// walk resolves affected peers in two buckets, by how far each change propagates.
//
// BOTH-SIDES — the rule itself changed (an explicit policy edit, or a policy whose
// posture check changed). Source AND destination refresh, so each such policy is
// walked on both sides.
//
// OPPOSITE-SIDE — an endpoint moved but no rule changed. For each policy the change
// touches we fold only the side AWAY from the change:
//   - a changed peer/group sits ON a policy side -> fold the opposite side;
//   - a changed router/resource/network sits on a NETWORK -> fold the SOURCE side of
//     the policies whose destination reaches it (and the routers it implies).
//
// Routes, nameserver groups, DNS and embedded-proxy services distribute to their own
// member peers, outside the policy graph, and are folded here too.
func (r *resolver) walk() {
	for _, policy := range r.bothSidesPolicies() {
		r.foldPolicySide(policy, sideSource)
		r.foldPolicySide(policy, sideDestination)
	}

	if len(r.linkGroups) > 0 || len(r.changedPeers) > 0 {
		r.collectFromPolicies()
		r.collectFromRoutes()
		r.collectFromNameServers()
		r.collectFromDNSSettings()
		r.collectFromNetworkRouters()
		r.collectFromProxyServices()
	}

	r.collectFromChangedRoutes(r.change.Routes)
	r.collectFromChangedRouters(r.change.Routers)
	r.collectFromChangedResources(r.change.Resources)
	r.collectFromChangedNetworks(r.change.Networks)

	// The explicitly changed peers always refresh their own maps. OnPeersUpdated only
	// refreshes the resolver's output (it ignores the separately-passed changed peers),
	// so the changed peer reaches its own new map only via here. An offline/deleted
	// peer in the set is filtered downstream (filterConnectedAffectedPeers).
	addAll(r.affectedPeers, setToSlice(r.changedPeers))
	// OutputPeerIDs refresh themselves too, but unlike changedPeers their group
	// memberships were not seeded into the walk (only the changed group was).
	addAll(r.affectedPeers, r.change.OutputPeerIDs)

	// Distribution groups (nameserver/DNS) affect only their member peers: fold them
	// straight into affectedGroups so expand() maps them to members, without the
	// policy/route walk that linkGroups would trigger.
	addAll(r.affectedGroups, r.change.DistributionGroupIDs)
}

// bothSidesPolicies are the policies whose rule changed: the explicitly edited ones
// plus those gated by a changed posture check. walk folds both their sides.
func (r *resolver) bothSidesPolicies() []*types.Policy {
	policies := append([]*types.Policy(nil), r.change.Policies...)
	return r.appendPoliciesForPostureChecks(policies, r.change.PostureCheckIDs)
}

type resolver struct {
	ctx       context.Context
	snap      *Snapshot
	accountID string
	change    Change

	// Inputs — what changed. Set once at construction, read-only during the walk
	// (except linkGroups, which collectFromExplicitResources also seeds).
	//
	// linkGroups is the MATCH set: caller-changed groups ∪ the groups of changed
	// peers ∪ changed-resource groups. A rule/route/router matches the change when
	// one of its groups is here — used only to find the opposite side to fold.
	//
	// outputGroups is the FOLD-WHOLE-GROUP set: ONLY Change.ChangedGroupIDs. When a
	// matched group is here, its whole membership is affected. A peer-seeded group
	// is in linkGroups but NOT outputGroups, so it folds only the changed peer
	// (changedPeers), never its siblings.
	linkGroups   map[string]struct{}
	outputGroups map[string]struct{}
	changedPeers map[string]struct{}

	// Outputs — the answer. The only sets the walk accumulates into. affectedGroups
	// is expanded to its member peers in expand().
	affectedGroups map[string]struct{}
	affectedPeers  map[string]struct{}
}

// policies returns the account's ENABLED policies from the snapshot. Disabled
// policies grant no access, so the walk skips them when scanning existing account
// data. Explicitly changed policies (Change.Policies, via bothSidesPolicies) are
// processed regardless of Enabled, so disabling one still refreshes its peers.
func (r *resolver) policies() []*types.Policy {
	enabled := make([]*types.Policy, 0, len(r.snap.policies))
	for _, policy := range r.snap.policies {
		if policy != nil && policy.Enabled {
			enabled = append(enabled, policy)
		}
	}
	return enabled
}

// networkResources / networkRouters return the account's ENABLED resources/routers
// from the snapshot. Disabled objects route to nobody, so the walk skips them when
// it scans existing account data. The explicitly changed objects in the Change are
// processed regardless of Enabled (collectFromChanged*), so disabling one still
// refreshes the peers that lose access.
func (r *resolver) networkResources() []*resourceTypes.NetworkResource {
	enabled := make([]*resourceTypes.NetworkResource, 0, len(r.snap.resources))
	for _, resource := range r.snap.resources {
		if resource.Enabled {
			enabled = append(enabled, resource)
		}
	}
	return enabled
}

func (r *resolver) networkRouters() []*routerTypes.NetworkRouter {
	enabled := make([]*routerTypes.NetworkRouter, 0, len(r.snap.routers))
	for _, router := range r.snap.routers {
		if router.Enabled {
			enabled = append(enabled, router)
		}
	}
	return enabled
}

// peerIDsForGroups maps a group set to its member peer IDs via the preloaded index.
func (r *resolver) peerIDsForGroups(groups map[string]struct{}) []string {
	seen := make(map[string]struct{})
	var ids []string
	for gID := range groups {
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
	peerIDs := r.peerIDsForGroups(r.affectedGroups)

	log.WithContext(r.ctx).Tracef("affectedpeers expand: account=%s affectedGroups=%v -> %d group-member peers; direct peers=%v",
		r.accountID, setToSlice(r.affectedGroups), len(peerIDs), setToSlice(r.affectedPeers))

	seen := make(map[string]struct{}, len(peerIDs))
	for _, id := range peerIDs {
		seen[id] = struct{}{}
	}
	for id := range r.affectedPeers {
		if _, ok := seen[id]; !ok {
			peerIDs = append(peerIDs, id)
			seen[id] = struct{}{}
		}
	}

	// Fold in removed peers only when their group is linked (in affectedGroups).
	for groupID, removed := range r.change.RemovedPeersByGroup {
		if _, linked := r.affectedGroups[groupID]; !linked {
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

// ruleSideGroups / ruleSideResource return the groups and the resource on the given
// side of a rule.
func ruleSideGroups(rule *types.PolicyRule, side policySide) []string {
	if side == sideDestination {
		return rule.Destinations
	}
	return rule.Sources
}

func ruleSideResource(rule *types.PolicyRule, side policySide) types.Resource {
	if side == sideDestination {
		return rule.DestinationResource
	}
	return rule.SourceResource
}

// foldPolicySide folds one side of a policy down to affected peers: its groups
// (resolved to members in expand) and its direct peer. When the side is the
// DESTINATION and references a network resource (directly or via a destination
// group's resources), it also folds the routers that serve that resource's network
// — a destination resource is reached through its routers. A resource on the SOURCE
// side routes to nobody (GetPoliciesForNetworkResource matches destinations only),
// so the router hop is destination-only.
func (r *resolver) foldPolicySide(policy *types.Policy, side policySide) {
	if policy == nil {
		return
	}
	for _, rule := range policy.Rules {
		addAll(r.affectedGroups, ruleSideGroups(rule, side))
		res := ruleSideResource(rule, side)
		if res.Type == types.ResourceTypePeer && res.ID != "" {
			r.affectedPeers[res.ID] = struct{}{}
		}
	}
	if side == sideDestination {
		r.foldRoutersForResources(r.policyDestinationResourceIDs(policy))
	}
}

// appendPoliciesForPostureChecks appends every policy that references a changed
// posture check (a rule change, so walk both sides).
func (r *resolver) appendPoliciesForPostureChecks(policies []*types.Policy, postureCheckIDs []string) []*types.Policy {
	if len(postureCheckIDs) == 0 {
		return policies
	}
	ids := toSet(postureCheckIDs)
	for _, policy := range r.policies() {
		if !policyReferencesPostureChecks(policy, ids) || !policy.Enabled {
			continue
		}
		log.WithContext(r.ctx).Tracef("appendPoliciesForPostureChecks: policy %s (%s) references changed posture checks %v -> both-sides policy",
			policy.ID, policy.Name, postureCheckIDs)
		policies = append(policies, policy)
	}
	return policies
}

// collectFromPolicies folds, for every policy whose rule a changed group or peer
// touches, only the OPPOSITE side (down to peers, incl. destination routers), plus
// the changed entity's own side: the changed group's whole membership when the
// group itself changed (outputGroups), or the changed peer alone when matched via a
// peer-seeded group (never its co-members).
func (r *resolver) collectFromPolicies() {
	for _, policy := range r.policies() {
		for _, rule := range policy.Rules {
			if !rule.Enabled {
				continue // a disabled rule grants no access
			}
			r.foldRuleSideIfChanged(policy, rule, sideSource)
			r.foldRuleSideIfChanged(policy, rule, sideDestination)
		}
	}
}

// foldRuleSideIfChanged: when a changed group or direct peer sits on `side` of the
// rule, fold the opposite side fully (groups/peers + destination routers) and fold
// the changed entity's own side (the whole changed group, or the changed peer alone).
func (r *resolver) foldRuleSideIfChanged(policy *types.Policy, rule *types.PolicyRule, side policySide) {
	nearGroups := ruleSideGroups(rule, side)
	nearResource := ruleSideResource(rule, side)

	matchedByGroup := anyInSet(nearGroups, r.linkGroups)
	matchedByPeer := isDirectPeerInSet(nearResource, r.changedPeers)
	if !matchedByGroup && !matchedByPeer {
		return
	}

	// Opposite side, fully down to peers (a destination opposite also folds routers).
	r.foldPolicySideForRule(policy, rule, side.opposite())

	// Own side: fold the whole changed group's members only when the group itself
	// changed (outputGroups). A peer-seeded or link-only group is not folded here —
	// its siblings never refresh. The changed peers themselves are folded once, after
	// the walk (see walk()).
	for _, gID := range nearGroups {
		if _, ok := r.outputGroups[gID]; ok {
			r.affectedGroups[gID] = struct{}{}
		}
	}

	// When the changed side IS a destination, the resources it targets are reached
	// through their network's routers, so those routers refresh too (e.g. attaching a
	// resource to a destination group, or a changed destination group/resource).
	if side == sideDestination {
		r.foldRoutersForResources(r.ruleDestinationResourceIDs(rule))
	}
}

// foldPolicySideForRule folds one side of a single rule (groups + direct peer), and
// for a destination side the routers of that rule's destination resources.
func (r *resolver) foldPolicySideForRule(policy *types.Policy, rule *types.PolicyRule, side policySide) {
	addAll(r.affectedGroups, ruleSideGroups(rule, side))
	res := ruleSideResource(rule, side)
	if res.Type == types.ResourceTypePeer && res.ID != "" {
		r.affectedPeers[res.ID] = struct{}{}
	}
	if side == sideDestination {
		r.foldRoutersForResources(r.ruleDestinationResourceIDs(rule))
	}
}

// collectFromChangedRoutes folds an explicitly changed route's own groups and peer.
func (r *resolver) collectFromChangedRoutes(routes []*route.Route) {
	for _, rt := range routes {
		if rt == nil {
			continue
		}
		log.WithContext(r.ctx).Tracef("collectFromChangedRoutes: changed route %s -> folding groups=%v peerGroups=%v accessControlGroups=%v peer=%q",
			rt.ID, rt.Groups, rt.PeerGroups, rt.AccessControlGroups, rt.Peer)
		addAll(r.affectedGroups, rt.Groups, rt.PeerGroups, rt.AccessControlGroups)
		if rt.Peer != "" {
			r.affectedPeers[rt.Peer] = struct{}{}
		}
	}
}

// collectFromChangedRouters: a changed router refreshes its OWN backing peer/groups
// (the changed entity) and the SOURCE side of every policy reaching a resource on
// its network (the router serves the whole network). Sibling routers on the network
// are independent and are NOT folded. Passing the old router state keeps a repointed
// router's previous backing affected without a post-commit read.
func (r *resolver) collectFromChangedRouters(routers []*routerTypes.NetworkRouter) {
	for _, router := range routers {
		if router == nil {
			continue
		}
		log.WithContext(r.ctx).Tracef("collectFromChangedRouters: changed router %s on network %s -> folding its own peerGroups=%v peer=%q + sources reaching network resources",
			router.ID, router.NetworkID, router.PeerGroups, router.Peer)
		addAll(r.affectedGroups, router.PeerGroups)
		if router.Peer != "" {
			r.affectedPeers[router.Peer] = struct{}{}
		}
		if router.NetworkID != "" {
			r.foldPolicySourcesForResources(r.networkResourceIDs(router.NetworkID))
		}
	}
}

// collectFromChangedResources: a changed resource refreshes the SOURCE side of the
// policies targeting EXACTLY that resource — directly, or via one of the resource's
// own groups (old∪new across the change, so a now-detached group's sources still
// refresh) — plus the routers serving its network (the resource is reached through
// them). It does not touch sibling resources on the same network.
func (r *resolver) collectFromChangedResources(resources []*resourceTypes.NetworkResource) {
	for _, resource := range resources {
		if resource == nil {
			continue
		}
		log.WithContext(r.ctx).Tracef("collectFromChangedResources: changed resource %s on network %s (groups %v) -> folding sources of policies targeting it + its network's routers",
			resource.ID, resource.NetworkID, resource.GroupIDs)
		r.foldPolicySourcesForResource(resource.ID, resource.GroupIDs)
		if resource.NetworkID != "" {
			r.foldRoutersOnNetworks(map[string]struct{}{resource.NetworkID: {}})
		}
	}
}

// foldPolicySourcesForResource folds the source side of every policy whose
// destination is the given resource — referenced directly, or via any of the given
// groups (the resource's own old∪new groups, which captures a detached group).
func (r *resolver) foldPolicySourcesForResource(resourceID string, groupIDs []string) {
	groups := toSet(groupIDs)
	for _, policy := range r.policies() {
		if !policyTargetsResourceOrGroups(policy, resourceID, groups) {
			continue
		}
		log.WithContext(r.ctx).Tracef("foldPolicySourcesForResource: policy %s (%s) targets changed resource %s -> folding its source groups/peers", policy.ID, policy.Name, resourceID)
		collectPolicySources(policy, r.affectedGroups, r.affectedPeers)
	}
}

// policyTargetsResourceOrGroups reports whether a policy's destination is the given
// resource directly, or one of the given destination groups.
func policyTargetsResourceOrGroups(policy *types.Policy, resourceID string, groups map[string]struct{}) bool {
	if policy == nil {
		return false
	}
	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}
		if rule.DestinationResource.Type != types.ResourceTypePeer && rule.DestinationResource.ID == resourceID && resourceID != "" {
			return true
		}
		if anyInSet(rule.Destinations, groups) {
			return true
		}
	}
	return false
}

// collectFromChangedNetworks: a changed network refreshes the SOURCE side of the
// policies reaching any of its resources, plus its routers. A network has no
// groups/peers of its own.
func (r *resolver) collectFromChangedNetworks(networks []*networkTypes.Network) {
	for _, network := range networks {
		if network == nil || network.ID == "" {
			continue
		}
		log.WithContext(r.ctx).Tracef("collectFromChangedNetworks: changed network %s -> folding sources reaching its resources + its routers", network.ID)
		resourceIDs := r.networkResourceIDs(network.ID)
		r.foldPolicySourcesForResources(resourceIDs)
		r.foldRoutersOnNetworks(map[string]struct{}{network.ID: {}})
	}
}

// foldPolicySourcesForResources folds the source groups/peers of every policy whose
// destination targets one of resourceIDs (directly or via a destination group).
func (r *resolver) foldPolicySourcesForResources(resourceIDs map[string]struct{}) {
	if len(resourceIDs) == 0 {
		return
	}
	for _, policy := range r.policies() {
		if r.policyTargetsResources(policy, resourceIDs) {
			log.WithContext(r.ctx).Tracef("foldPolicySourcesForResources: policy %s (%s) targets a changed resource -> folding its source groups/peers", policy.ID, policy.Name)
			collectPolicySources(policy, r.affectedGroups, r.affectedPeers)
		}
	}
}

// collectFromRoutes folds, per matched route, the OPPOSITE side(s) fully and the
// matched side's own groups only on a whole-group change (outputGroups). A route has
// three peer sides — routing (Peer/PeerGroups), consumer (Groups) and ACL
// (AccessControlGroups) — that each refresh the others; the changed side's own group
// folds its siblings only when the group itself changed, never on a one-peer move.
func (r *resolver) collectFromRoutes() {
	for _, rt := range r.snap.routes {
		if !rt.Enabled {
			continue // disabled routes route to nobody; skip existing account data
		}
		routing := anyInSet(rt.PeerGroups, r.linkGroups) || (rt.Peer != "" && isInSet(rt.Peer, r.changedPeers))
		consumer := anyInSet(rt.Groups, r.linkGroups)
		acl := anyInSet(rt.AccessControlGroups, r.linkGroups)
		if !routing && !consumer && !acl {
			continue
		}
		log.WithContext(r.ctx).Tracef("collectFromRoutes: route %s matched (routing=%t consumer=%t acl=%t) -> folding opposite sides; own side gated on outputGroups",
			rt.ID, routing, consumer, acl)
		r.foldRouteSide(rt.PeerGroups, routing)
		r.foldRouteSide(rt.Groups, consumer)
		r.foldRouteSide(rt.AccessControlGroups, acl)
		// The single routing Peer folds when the routing side is the OPPOSITE of the
		// match (consumer/acl need it), or when that very peer is the change.
		if rt.Peer != "" && (consumer || acl || isInSet(rt.Peer, r.changedPeers)) {
			r.affectedPeers[rt.Peer] = struct{}{}
		}
	}
}

// foldRouteSide folds a route side: when this side is the one that matched, fold its
// groups only on a whole-group change (outputGroups) so siblings of a single moved
// peer stay put; otherwise it is an opposite side and folds fully.
func (r *resolver) foldRouteSide(groups []string, matchedHere bool) {
	if matchedHere {
		r.foldOutputGroups(groups)
		return
	}
	addAll(r.affectedGroups, groups)
}

// foldOutputGroups folds only the groups that the caller reported as wholly changed
// (outputGroups). Used for a matched object's OWN side, where a peer-seeded or
// link-only group must not pull in its siblings.
func (r *resolver) foldOutputGroups(groups ...[]string) {
	for _, gs := range groups {
		for _, gID := range gs {
			if _, ok := r.outputGroups[gID]; ok {
				r.affectedGroups[gID] = struct{}{}
			}
		}
	}
}

func (r *resolver) collectFromNameServers() {
	if len(r.linkGroups) == 0 {
		return
	}
	for _, ns := range r.snap.nsGroups {
		if anyInSet(ns.Groups, r.linkGroups) {
			// A nameserver group has no opposite side: a peer's DNS config depends only
			// on its own membership, so a one-peer move refreshes that peer alone (folded
			// elsewhere). Fold the referenced groups only on a whole-group change.
			log.WithContext(r.ctx).Tracef("collectFromNameServers: nameserver group %s references a linked group -> folding its groups %v (outputGroups only)", ns.ID, ns.Groups)
			r.foldOutputGroups(ns.Groups)
		}
	}
}

func (r *resolver) collectFromDNSSettings() {
	if len(r.linkGroups) == 0 || r.snap.dnsSettings == nil {
		return
	}
	for _, gID := range r.snap.dnsSettings.DisabledManagementGroups {
		if _, ok := r.linkGroups[gID]; ok {
			log.WithContext(r.ctx).Tracef("collectFromDNSSettings: changed group %s is in DisabledManagementGroups -> folding it", gID)
			r.affectedGroups[gID] = struct{}{}
		}
	}
}

// collectFromNetworkRouters handles a changed group/peer that BACKS a router (the
// routing peer set moved): the router's own peers refresh and so do the sources of
// the policies reaching its network's resources. Sibling routers on the network are
// independent and are not folded.
func (r *resolver) collectFromNetworkRouters() {
	for _, router := range r.networkRouters() {
		matchedByGroup := anyInSet(router.PeerGroups, r.linkGroups)
		matchedByPeer := router.Peer != "" && len(r.changedPeers) > 0 && isInSet(router.Peer, r.changedPeers)
		if !matchedByGroup && !matchedByPeer {
			continue
		}
		log.WithContext(r.ctx).Tracef("collectFromNetworkRouters: router %s on network %s matched (byGroup=%t byPeer=%t) -> folding its peerGroups=%v peer=%q (own groups on outputGroups) + sources reaching network resources",
			router.ID, router.NetworkID, matchedByGroup, matchedByPeer, router.PeerGroups, router.Peer)
		// The backing PeerGroups are the matched (own) side: fold them only on a
		// whole-group change so a one-peer move does not wake sibling backing peers. The
		// opposite side (policy sources reaching the network) is folded below.
		r.foldOutputGroups(router.PeerGroups)
		if router.Peer != "" {
			r.affectedPeers[router.Peer] = struct{}{}
		}
		if router.NetworkID != "" {
			r.foldPolicySourcesForResources(r.networkResourceIDs(router.NetworkID))
		}
	}
}

func (r *resolver) collectFromProxyServices() {
	if len(r.snap.proxyByCluster) == 0 || len(r.snap.services) == 0 {
		return
	}
	services, proxyByCluster := r.snap.services, r.snap.proxyByCluster

	expanded := r.expandChangedPeersWithGroups()

	for _, svc := range services {
		if svc == nil || !svc.Enabled {
			continue // a disabled service proxies nothing; skip existing account data
		}
		proxyPeers := proxyByCluster[svc.ProxyCluster]
		if len(proxyPeers) == 0 {
			continue
		}
		matchedByPeer := serviceMatchesChangedPeers(svc, proxyPeers, expanded)
		matchedByAccessGroup := anyInSet(svc.AccessGroups, r.linkGroups)
		if !matchedByPeer && !matchedByAccessGroup {
			continue
		}
		log.WithContext(r.ctx).Tracef("collectFromProxyServices: service %s (cluster=%s) matched (byProxyOrTargetPeer=%t byAccessGroup=%t) -> folding %d proxy peers, peer targets; access groups %v on outputGroups only",
			svc.ID, svc.ProxyCluster, matchedByPeer, matchedByAccessGroup, len(proxyPeers), svc.AccessGroups)
		for _, pid := range proxyPeers {
			r.affectedPeers[pid] = struct{}{}
		}
		for _, target := range svc.Targets {
			if !target.Enabled {
				continue // a disabled target forwards nothing
			}
			if target.TargetType == rpservice.TargetTypePeer && target.TargetId != "" {
				r.affectedPeers[target.TargetId] = struct{}{}
			}
		}
		// AccessGroups are the matched (own) side with no opposite to fold: a member's
		// proxy access is self-contained, so a one-peer move refreshes that peer alone.
		// Fold the groups only on a whole-group change.
		r.foldOutputGroups(svc.AccessGroups)
	}
}

func (r *resolver) expandChangedPeersWithGroups() map[string]struct{} {
	if len(r.linkGroups) == 0 {
		return r.changedPeers
	}
	ids := r.peerIDsForGroups(r.linkGroups)
	if len(ids) == 0 {
		return r.changedPeers
	}
	merged := make(map[string]struct{}, len(r.changedPeers)+len(ids))
	for id := range r.changedPeers {
		merged[id] = struct{}{}
	}
	for _, id := range ids {
		merged[id] = struct{}{}
	}
	return merged
}

// foldRoutersForResources folds the routers serving the networks of the given
// resources (a destination resource is reached through its network's routers). It is
// the resource -> network -> router hop used by foldPolicySide for a destination.
func (r *resolver) foldRoutersForResources(resourceIDs map[string]struct{}) {
	if len(resourceIDs) == 0 {
		return
	}
	r.foldRoutersOnNetworks(r.resourceNetworkIDs(resourceIDs))
}

// ruleDestinationResourceIDs returns the destination resource IDs of a single rule:
// the direct DestinationResource plus the resources of its destination groups.
func (r *resolver) ruleDestinationResourceIDs(rule *types.PolicyRule) map[string]struct{} {
	resourceIDs := make(map[string]struct{})
	if rule.DestinationResource.Type != types.ResourceTypePeer && rule.DestinationResource.ID != "" {
		resourceIDs[rule.DestinationResource.ID] = struct{}{}
	}
	r.addGroupResourceIDs(toSet(rule.Destinations), resourceIDs)
	return resourceIDs
}

// networkResourceIDs returns the IDs of all resources on the given network.
func (r *resolver) networkResourceIDs(networkID string) map[string]struct{} {
	resourceIDs := make(map[string]struct{})
	for _, resource := range r.networkResources() {
		if resource.NetworkID == networkID {
			resourceIDs[resource.ID] = struct{}{}
		}
	}
	return resourceIDs
}

func (r *resolver) foldRoutersOnNetworks(networkIDs map[string]struct{}) {
	for _, router := range r.networkRouters() {
		if _, ok := networkIDs[router.NetworkID]; !ok {
			continue
		}
		log.WithContext(r.ctx).Tracef("bridgeRoutersToSources: router %s serves affected network %s -> folding peerGroups=%v peer=%q",
			router.ID, router.NetworkID, router.PeerGroups, router.Peer)
		addAll(r.affectedGroups, router.PeerGroups)
		if router.Peer != "" {
			r.affectedPeers[router.Peer] = struct{}{}
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
		if !rule.Enabled {
			continue
		}
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

// collectPolicySources folds the source groups/peers of a snapshot policy's enabled
// rules (a disabled rule grants no access).
func collectPolicySources(policy *types.Policy, groups, peers map[string]struct{}) {
	for _, rule := range policy.Rules {
		if !rule.Enabled {
			continue
		}
		addAll(groups, rule.Sources)
		if rule.SourceResource.Type == types.ResourceTypePeer && rule.SourceResource.ID != "" {
			peers[rule.SourceResource.ID] = struct{}{}
		}
	}
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
		if !target.Enabled || target.TargetType != rpservice.TargetTypePeer || target.TargetId == "" {
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
