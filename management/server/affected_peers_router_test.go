package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/server/affectedpeers"
	"github.com/netbirdio/netbird/management/server/groups"
	"github.com/netbirdio/netbird/management/server/networks"
	"github.com/netbirdio/netbird/management/server/networks/resources"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	"github.com/netbirdio/netbird/management/server/networks/routers"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// routerScenario captures the topology from the bug report:
//
//	network ── router (routing peer) ── resource (in resourceGroup)
//	independent peer ──(policy: source -> resource)──> resource
//
// The routing peer must be refreshed when a policy grants a source peer access
// to the resource, because the network map connects the source peer to the
// routing peer at compute time (Account.GetPoliciesForNetworkResource +
// addNetworksRoutingPeers). The routing peer is NOT a member of the resource
// group, so static group/peer resolution alone cannot find it.
type routerScenario struct {
	manager       *DefaultAccountManager
	updateManager *update_channel.PeersUpdateManager
	accountID     string
	networkID     string

	sourcePeerID  string // independent peer that the policy grants access from
	sourceGroupID string // group containing the source peer

	routerPeerID      string // peer acting as the routing peer (direct router.Peer)
	routerGroupPeerID string // peer that is a member of routerPeerGroup
	routerPeerGroupID string // group used for router.PeerGroups

	resourceID      string // network resource
	resourceGroupID string // group whose member is the resource (no peers)

	unrelatedPeerID string // peer in no relevant entity
}

// setupRouterScenario builds the topology above with the default policy removed
// and channels NOT yet created, so callers control exactly when updates can flow.
func setupRouterScenario(t *testing.T, directRouterPeer bool) *routerScenario {
	t.Helper()

	manager, updateManager, err := createManager(t)
	require.NoError(t, err)

	ctx := context.Background()

	account, err := createAccount(manager, "router_scenario", userID, "")
	require.NoError(t, err)
	accountID := account.Id

	// Remove the default policy so AddPeer/CreateGroup don't schedule unrelated updates.
	policies, err := manager.Store.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)
	for _, p := range policies {
		require.NoError(t, manager.Store.DeletePolicy(ctx, accountID, p.ID))
	}

	setupKey, err := manager.CreateSetupKey(ctx, accountID, "rs-key", types.SetupKeyReusable, time.Hour, nil, 999, userID, false, false)
	require.NoError(t, err)

	sourcePeer := addPeerToAccount(t, manager, accountID, setupKey.Key)
	routerPeer := addPeerToAccount(t, manager, accountID, setupKey.Key)
	routerGroupPeer := addPeerToAccount(t, manager, accountID, setupKey.Key)
	unrelatedPeer := addPeerToAccount(t, manager, accountID, setupKey.Key)

	const (
		sourceGroupID     = "rs-source-grp"
		routerPeerGroupID = "rs-router-grp"
		resourceGroupID   = "rs-resource-grp"
	)

	for _, g := range []*types.Group{
		{ID: sourceGroupID, Name: "rs-source", Peers: []string{sourcePeer.ID}},
		{ID: routerPeerGroupID, Name: "rs-router", Peers: []string{routerGroupPeer.ID}},
		{ID: resourceGroupID, Name: "rs-resource"}, // intentionally peerless; the resource is its only member
	} {
		require.NoError(t, manager.CreateGroup(ctx, accountID, userID, g))
	}

	permissionsManager := permissions.NewManager(manager.Store)
	groupsManager := groups.NewManager(manager.Store, permissionsManager, manager)
	resourcesManager := resources.NewManager(manager.Store, permissionsManager, groupsManager, manager, manager.serviceManager)
	routersManager := routers.NewManager(manager.Store, permissionsManager, manager)
	networksManager := networks.NewManager(manager.Store, permissionsManager, resourcesManager, routersManager, manager)

	network, err := networksManager.CreateNetwork(ctx, userID, &networkTypes.Network{
		ID:        "rs-network",
		AccountID: accountID,
		Name:      "rs-network",
	})
	require.NoError(t, err)

	resource, err := resourcesManager.CreateResource(ctx, userID, &resourceTypes.NetworkResource{
		AccountID: accountID,
		NetworkID: network.ID,
		Name:      "rs-resource-host",
		Address:   "10.20.30.0/24",
		GroupIDs:  []string{resourceGroupID},
		Enabled:   true,
	})
	require.NoError(t, err)

	router := &routerTypes.NetworkRouter{
		ID:         "rs-router",
		NetworkID:  network.ID,
		AccountID:  accountID,
		Masquerade: true,
		Metric:     9999,
		Enabled:    true,
	}
	if directRouterPeer {
		router.Peer = routerPeer.ID
	} else {
		router.PeerGroups = []string{routerPeerGroupID}
	}
	_, err = routersManager.CreateRouter(ctx, userID, router)
	require.NoError(t, err)

	return &routerScenario{
		manager:           manager,
		updateManager:     updateManager,
		accountID:         accountID,
		networkID:         network.ID,
		sourcePeerID:      sourcePeer.ID,
		sourceGroupID:     sourceGroupID,
		routerPeerID:      routerPeer.ID,
		routerGroupPeerID: routerGroupPeer.ID,
		routerPeerGroupID: routerPeerGroupID,
		resourceID:        resource.ID,
		resourceGroupID:   resourceGroupID,
		unrelatedPeerID:   unrelatedPeer.ID,
	}
}

// peerToResourcePolicy builds a policy granting the source group access to the
// resource, referencing the resource by its group in the rule destination.
func peerToResourcePolicyByGroup(sourceGroupID, resourceGroupID string) *types.Policy {
	return &types.Policy{
		Enabled: true,
		Name:    "peer-to-resource-by-group",
		Rules: []*types.PolicyRule{
			{
				Enabled:      true,
				Sources:      []string{sourceGroupID},
				Destinations: []string{resourceGroupID},
				Action:       types.PolicyTrafficActionAccept,
			},
		},
	}
}

// peerToResourcePolicyByResource builds a policy referencing the resource
// directly via DestinationResource rather than its group.
func peerToResourcePolicyByResource(sourceGroupID, resourceID string) *types.Policy {
	return &types.Policy{
		Enabled: true,
		Name:    "peer-to-resource-by-resource",
		Rules: []*types.PolicyRule{
			{
				Enabled:             true,
				Sources:             []string{sourceGroupID},
				DestinationResource: types.Resource{ID: resourceID, Type: types.ResourceTypeHost},
				Action:              types.PolicyTrafficActionAccept,
			},
		},
	}
}

// resolvePolicyAffected mirrors SavePolicy's resolution: resolve the affected
// peers for the given policy.
func (s *routerScenario) resolvePolicyAffected(ctx context.Context, policy *types.Policy) []string {
	change := affectedpeers.Change{Policies: []*types.Policy{policy}}
	snap, err := affectedpeers.Load(ctx, s.manager.Store, s.accountID, change)
	if err != nil {
		return nil
	}
	return snap.Expand(ctx, s.accountID, change)
}

func TestAffectedPeers_SourcePeer_DirectRouter(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	policy := peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID)
	affected := s.resolvePolicyAffected(ctx, policy)

	assert.Contains(t, affected, s.sourcePeerID, "source peer must be affected")
}

func TestAffectedPeers_RoutingPeer_DirectRouter(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	policy := peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID)
	affected := s.resolvePolicyAffected(ctx, policy)

	// BUG: the direct routing peer serves the resource's subnet to the source
	// peer, so it must be refreshed when the policy is created. The policy path
	// only resolves the literal rule groups (source group + resource group);
	// the resource group has no peer members and the router peer is reachable
	// only through the network, so it is dropped.
	assert.Contains(t, affected, s.routerPeerID,
		"routing peer (router.Peer) serving the resource must be affected by a policy granting access to it")
}

func TestAffectedPeers_RoutingPeer_RouterPeerGroups(t *testing.T) {
	s := setupRouterScenario(t, false)
	ctx := context.Background()

	policy := peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID)
	affected := s.resolvePolicyAffected(ctx, policy)

	// Router defined via PeerGroups instead of a direct peer.
	assert.Contains(t, affected, s.routerGroupPeerID,
		"routing peer (router.PeerGroups member) serving the resource must be affected")
}

func TestAffectedPeers_DestResource_RoutingPeer_DirectRouter(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	policy := peerToResourcePolicyByResource(s.sourceGroupID, s.resourceID)
	affected := s.resolvePolicyAffected(ctx, policy)

	// When the resource is referenced via DestinationResource, RuleGroups()
	// returns only the source group and the resource ID is not a peer, so
	// collectPolicyAffectedGroupsAndPeers yields nothing for the destination at
	// all. The routing peer is dropped here too.
	assert.Contains(t, affected, s.routerPeerID,
		"routing peer must be affected when the resource is referenced via DestinationResource")
}

func TestAffectedPeers_DestResource_RoutingPeer_RouterPeerGroups(t *testing.T) {
	s := setupRouterScenario(t, false)
	ctx := context.Background()

	policy := peerToResourcePolicyByResource(s.sourceGroupID, s.resourceID)
	affected := s.resolvePolicyAffected(ctx, policy)

	assert.Contains(t, affected, s.routerGroupPeerID,
		"routing peer (PeerGroups) must be affected when the resource is referenced via DestinationResource")
}

func TestAffectedPeers_SourceResourcePeer_RoutingPeer(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	// Source expressed as a direct peer (SourceResource), destination as resource group.
	policy := &types.Policy{
		Enabled: true,
		Name:    "sourceResource-peer-to-resource",
		Rules: []*types.PolicyRule{
			{
				Enabled:        true,
				SourceResource: types.Resource{ID: s.sourcePeerID, Type: types.ResourceTypePeer},
				Destinations:   []string{s.resourceGroupID},
				Action:         types.PolicyTrafficActionAccept,
			},
		},
	}
	affected := s.resolvePolicyAffected(ctx, policy)

	// The direct source peer IS picked up (collectPolicyAffectedGroupsAndPeers
	// handles SourceResource peers), but the routing peer is still missing.
	assert.Contains(t, affected, s.sourcePeerID, "direct source peer must be affected")
	assert.Contains(t, affected, s.routerPeerID, "routing peer must be affected")
}

func TestAffectedPeers_PolicyToResource_UnrelatedPeerNotAffected(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	policy := peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID)
	affected := s.resolvePolicyAffected(ctx, policy)

	// Guard against an over-broad fix: a peer in no relevant entity must never
	// be pulled in.
	assert.NotContains(t, affected, s.unrelatedPeerID, "unrelated peer must not be affected")
}

func TestAffectedPeers_ResourceSideBridgesToRoutingPeer_DirectRouter(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	// A pre-existing policy grants the source group access to the resource.
	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
	require.NoError(t, err)

	// Drive an update through the resource manager and assert the routing peer
	// is among the affected set by observing the channel. This path walks
	// policies whose destinations reference the resource's groups, folds in the
	// source groups, and loads the network's routers, so it reaches both the
	// source peer and the routing peer.
	permissionsManager := permissions.NewManager(s.manager.Store)
	groupsManager := groups.NewManager(s.manager.Store, permissionsManager, s.manager)
	rm := resources.NewManager(s.manager.Store, permissionsManager, groupsManager, s.manager, s.manager.serviceManager)

	srcCh := s.updateManager.CreateChannel(ctx, s.sourcePeerID)
	routerCh := s.updateManager.CreateChannel(ctx, s.routerPeerID)
	t.Cleanup(func() {
		s.updateManager.CloseChannel(ctx, s.sourcePeerID)
		s.updateManager.CloseChannel(ctx, s.routerPeerID)
	})

	done := make(chan struct{})
	go func() {
		peerShouldReceiveUpdate(t, srcCh)
		peerShouldReceiveUpdate(t, routerCh)
		close(done)
	}()

	_, err = rm.UpdateResource(ctx, userID, &resourceTypes.NetworkResource{
		ID:        s.resourceID,
		AccountID: s.accountID,
		NetworkID: s.networkID,
		Name:      "rs-resource-host",
		Address:   "10.20.30.0/24",
		GroupIDs:  []string{s.resourceGroupID},
		Enabled:   true,
	})
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(peerUpdateTimeout):
		t.Error("timeout: resource update did not refresh source peer + routing peer")
	}
}

// settleAffectedUpdates waits for in-flight async updates to arrive, then drains
// every given channel so subsequent assertions start from a clean slate.
//
// Setup (CreateNetwork/CreateResource/CreateRouter) fires async UpdateAffectedPeers
// goroutines; draining first means the assertion only observes updates from the
// action under test, not setup stragglers.
func settleAffectedUpdates(chans ...<-chan *network_map.UpdateMessage) {
	time.Sleep(300 * time.Millisecond)
	for _, ch := range chans {
		drainPeerUpdates(ch)
	}
}

func TestAffectedPeers_E2E_CreatePolicy_RoutingPeer_DirectRouter(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	srcCh := s.updateManager.CreateChannel(ctx, s.sourcePeerID)
	routerCh := s.updateManager.CreateChannel(ctx, s.routerPeerID)
	unrelatedCh := s.updateManager.CreateChannel(ctx, s.unrelatedPeerID)
	t.Cleanup(func() {
		s.updateManager.CloseChannel(ctx, s.sourcePeerID)
		s.updateManager.CloseChannel(ctx, s.routerPeerID)
		s.updateManager.CloseChannel(ctx, s.unrelatedPeerID)
	})

	settleAffectedUpdates(srcCh, routerCh, unrelatedCh)

	done := make(chan struct{})
	go func() {
		peerShouldReceiveUpdate(t, srcCh)
		peerShouldReceiveUpdate(t, routerCh)
		peerShouldNotReceiveUpdate(t, unrelatedCh)
		close(done)
	}()

	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(peerUpdateTimeout):
		t.Error("timeout: creating peer->resource policy did not refresh the routing peer")
	}
}

func TestAffectedPeers_E2E_CreatePolicy_RoutingPeer_RouterPeerGroups(t *testing.T) {
	s := setupRouterScenario(t, false)
	ctx := context.Background()

	srcCh := s.updateManager.CreateChannel(ctx, s.sourcePeerID)
	routerCh := s.updateManager.CreateChannel(ctx, s.routerGroupPeerID)
	t.Cleanup(func() {
		s.updateManager.CloseChannel(ctx, s.sourcePeerID)
		s.updateManager.CloseChannel(ctx, s.routerGroupPeerID)
	})

	settleAffectedUpdates(srcCh, routerCh)

	done := make(chan struct{})
	go func() {
		peerShouldReceiveUpdate(t, srcCh)
		peerShouldReceiveUpdate(t, routerCh)
		close(done)
	}()

	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(peerUpdateTimeout):
		t.Error("timeout: routing peer (PeerGroups) not refreshed on policy create")
	}
}

func TestAffectedPeers_E2E_DestResource_RoutingPeer(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	srcCh := s.updateManager.CreateChannel(ctx, s.sourcePeerID)
	routerCh := s.updateManager.CreateChannel(ctx, s.routerPeerID)
	t.Cleanup(func() {
		s.updateManager.CloseChannel(ctx, s.sourcePeerID)
		s.updateManager.CloseChannel(ctx, s.routerPeerID)
	})

	settleAffectedUpdates(srcCh, routerCh)

	done := make(chan struct{})
	go func() {
		peerShouldReceiveUpdate(t, srcCh)
		peerShouldReceiveUpdate(t, routerCh)
		close(done)
	}()

	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByResource(s.sourceGroupID, s.resourceID), true)
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(peerUpdateTimeout):
		t.Error("timeout: routing peer not refreshed when policy targets DestinationResource")
	}
}

func TestAffectedPeers_E2E_DeletePolicy_RoutingPeer(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	policy, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
	require.NoError(t, err)

	srcCh := s.updateManager.CreateChannel(ctx, s.sourcePeerID)
	routerCh := s.updateManager.CreateChannel(ctx, s.routerPeerID)
	t.Cleanup(func() {
		s.updateManager.CloseChannel(ctx, s.sourcePeerID)
		s.updateManager.CloseChannel(ctx, s.routerPeerID)
	})

	settleAffectedUpdates(srcCh, routerCh)

	done := make(chan struct{})
	go func() {
		peerShouldReceiveUpdate(t, srcCh)
		peerShouldReceiveUpdate(t, routerCh)
		close(done)
	}()

	require.NoError(t, s.manager.DeletePolicy(ctx, s.accountID, policy.ID, userID))

	select {
	case <-done:
	case <-time.After(peerUpdateTimeout):
		t.Error("timeout: deleting peer->resource policy did not refresh the routing peer")
	}
}

func (s *routerScenario) managers() (resources.Manager, routers.Manager, networks.Manager) {
	permissionsManager := permissions.NewManager(s.manager.Store)
	groupsManager := groups.NewManager(s.manager.Store, permissionsManager, s.manager)
	resourcesManager := resources.NewManager(s.manager.Store, permissionsManager, groupsManager, s.manager, s.manager.serviceManager)
	routersManager := routers.NewManager(s.manager.Store, permissionsManager, s.manager)
	networksManager := networks.NewManager(s.manager.Store, permissionsManager, resourcesManager, routersManager, s.manager)
	return resourcesManager, routersManager, networksManager
}

type secondTopology struct {
	networkID       string
	resourceID      string
	resourceGroupID string
	routerPeerID    string
}

func (s *routerScenario) addSecondTopology(t *testing.T, suffix string) secondTopology {
	t.Helper()
	ctx := context.Background()
	resourcesManager, routersManager, networksManager := s.managers()

	setupKey, err := s.manager.CreateSetupKey(ctx, s.accountID, "rs-key-"+suffix, types.SetupKeyReusable, time.Hour, nil, 999, userID, false, false)
	require.NoError(t, err)
	routerPeer := addPeerToAccount(t, s.manager, s.accountID, setupKey.Key)

	resourceGroupID := "rs-resource-grp-" + suffix
	require.NoError(t, s.manager.CreateGroup(ctx, s.accountID, userID, &types.Group{
		ID: resourceGroupID, Name: "rs-resource-" + suffix,
	}))

	network, err := networksManager.CreateNetwork(ctx, userID, &networkTypes.Network{
		ID:        "rs-network-" + suffix,
		AccountID: s.accountID,
		Name:      "rs-network-" + suffix,
	})
	require.NoError(t, err)

	resource, err := resourcesManager.CreateResource(ctx, userID, &resourceTypes.NetworkResource{
		AccountID: s.accountID,
		NetworkID: network.ID,
		Name:      "rs-resource-host-" + suffix,
		Address:   "10.40.50.0/24",
		GroupIDs:  []string{resourceGroupID},
		Enabled:   true,
	})
	require.NoError(t, err)

	_, err = routersManager.CreateRouter(ctx, userID, &routerTypes.NetworkRouter{
		NetworkID:  network.ID,
		AccountID:  s.accountID,
		Peer:       routerPeer.ID,
		Masquerade: true,
		Metric:     9999,
		Enabled:    true,
	})
	require.NoError(t, err)

	return secondTopology{
		networkID:       network.ID,
		resourceID:      resource.ID,
		resourceGroupID: resourceGroupID,
		routerPeerID:    routerPeer.ID,
	}
}

func TestAffectedPeers_E2E_UpdatePolicy_BothRoutingPeers(t *testing.T) {
	s := setupRouterScenario(t, true)
	second := s.addSecondTopology(t, "b")
	ctx := context.Background()

	policy, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
	require.NoError(t, err)

	srcCh := s.updateManager.CreateChannel(ctx, s.sourcePeerID)
	routerACh := s.updateManager.CreateChannel(ctx, s.routerPeerID)
	routerBCh := s.updateManager.CreateChannel(ctx, second.routerPeerID)
	t.Cleanup(func() {
		s.updateManager.CloseChannel(ctx, s.sourcePeerID)
		s.updateManager.CloseChannel(ctx, s.routerPeerID)
		s.updateManager.CloseChannel(ctx, second.routerPeerID)
	})

	settleAffectedUpdates(srcCh, routerACh, routerBCh)

	done := make(chan struct{})
	go func() {
		peerShouldReceiveUpdate(t, srcCh)
		peerShouldReceiveUpdate(t, routerACh)
		peerShouldReceiveUpdate(t, routerBCh)
		close(done)
	}()

	policy.Rules[0].Destinations = []string{second.resourceGroupID}
	_, err = s.manager.SavePolicy(ctx, s.accountID, userID, policy, false)
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(peerUpdateTimeout):
		t.Error("timeout: re-pointing the policy destination did not refresh both routing peers")
	}
}

func TestAffectedPeers_E2E_UpdatePolicy_AddSource(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	const secondSourceGroupID = "rs-source-grp-2"
	setupKey, err := s.manager.CreateSetupKey(ctx, s.accountID, "rs-key-2", types.SetupKeyReusable, time.Hour, nil, 999, userID, false, false)
	require.NoError(t, err)
	secondSourcePeer := addPeerToAccount(t, s.manager, s.accountID, setupKey.Key)
	require.NoError(t, s.manager.CreateGroup(ctx, s.accountID, userID, &types.Group{
		ID: secondSourceGroupID, Name: "rs-source-2", Peers: []string{secondSourcePeer.ID},
	}))

	policy, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
	require.NoError(t, err)

	newSrcCh := s.updateManager.CreateChannel(ctx, secondSourcePeer.ID)
	routerCh := s.updateManager.CreateChannel(ctx, s.routerPeerID)
	t.Cleanup(func() {
		s.updateManager.CloseChannel(ctx, secondSourcePeer.ID)
		s.updateManager.CloseChannel(ctx, s.routerPeerID)
	})

	settleAffectedUpdates(newSrcCh, routerCh)

	done := make(chan struct{})
	go func() {
		peerShouldReceiveUpdate(t, newSrcCh)
		peerShouldReceiveUpdate(t, routerCh)
		close(done)
	}()

	policy.Rules[0].Sources = []string{s.sourceGroupID, secondSourceGroupID}
	_, err = s.manager.SavePolicy(ctx, s.accountID, userID, policy, false)
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(peerUpdateTimeout):
		t.Error("timeout: adding a source group did not refresh the new source peer + routing peer")
	}
}

func TestAffectedPeers_E2E_DestResource_RouterPeerGroups(t *testing.T) {
	s := setupRouterScenario(t, false)
	ctx := context.Background()

	srcCh := s.updateManager.CreateChannel(ctx, s.sourcePeerID)
	routerCh := s.updateManager.CreateChannel(ctx, s.routerGroupPeerID)
	t.Cleanup(func() {
		s.updateManager.CloseChannel(ctx, s.sourcePeerID)
		s.updateManager.CloseChannel(ctx, s.routerGroupPeerID)
	})

	settleAffectedUpdates(srcCh, routerCh)

	done := make(chan struct{})
	go func() {
		peerShouldReceiveUpdate(t, srcCh)
		peerShouldReceiveUpdate(t, routerCh)
		close(done)
	}()

	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByResource(s.sourceGroupID, s.resourceID), true)
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(peerUpdateTimeout):
		t.Error("timeout: DestinationResource policy with PeerGroups router did not refresh the routing peer")
	}
}

func TestAffectedPeers_AllRoutingPeers_Network(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	_, routersManager, _ := s.managers()
	setupKey, err := s.manager.CreateSetupKey(ctx, s.accountID, "rs-key-r2", types.SetupKeyReusable, time.Hour, nil, 999, userID, false, false)
	require.NoError(t, err)
	secondRouterPeer := addPeerToAccount(t, s.manager, s.accountID, setupKey.Key)
	_, err = routersManager.CreateRouter(ctx, userID, &routerTypes.NetworkRouter{
		NetworkID:  s.networkID,
		AccountID:  s.accountID,
		Peer:       secondRouterPeer.ID,
		Masquerade: true,
		Metric:     9998,
		Enabled:    true,
	})
	require.NoError(t, err)

	affected := s.resolvePolicyAffected(ctx, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID))

	assert.Contains(t, affected, s.routerPeerID, "first routing peer must be affected")
	assert.Contains(t, affected, secondRouterPeer.ID, "second routing peer on the same network must also be affected")
}

func TestAffectedPeers_DisabledRouter(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	routers, err := s.manager.Store.GetNetworkRoutersByNetID(ctx, store.LockingStrengthNone, s.accountID, s.networkID)
	require.NoError(t, err)
	require.Len(t, routers, 1)
	routers[0].Enabled = false
	require.NoError(t, s.manager.Store.UpdateNetworkRouter(ctx, routers[0]))

	affected := s.resolvePolicyAffected(ctx, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID))

	assert.Contains(t, affected, s.sourcePeerID, "source peer must be affected")
	assert.Contains(t, affected, s.routerPeerID,
		"disabled router's peer must still be affected: Enabled must not gate affected-peers")
}

func TestAffectedPeers_DisabledResource(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	res, err := s.manager.Store.GetNetworkResourceByID(ctx, store.LockingStrengthNone, s.accountID, s.resourceID)
	require.NoError(t, err)
	res.Enabled = false
	require.NoError(t, s.manager.Store.SaveNetworkResource(ctx, res))

	affected := s.resolvePolicyAffected(ctx, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID))

	assert.Contains(t, affected, s.sourcePeerID, "source peer must be affected")
	assert.Contains(t, affected, s.routerPeerID,
		"disabled resource must still resolve the routing peer: Enabled must not gate affected-peers")
}

func TestAffectedPeers_DisabledRule(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	policy := peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID)
	policy.Rules[0].Enabled = false

	affected := s.resolvePolicyAffected(ctx, policy)

	assert.Contains(t, affected, s.routerPeerID,
		"disabled rule must still resolve the routing peer: Enabled must not gate affected-peers")
}

func TestAffectedPeers_MultiRule(t *testing.T) {
	s := setupRouterScenario(t, true)
	second := s.addSecondTopology(t, "c")
	ctx := context.Background()

	policy := &types.Policy{
		Enabled: true,
		Name:    "multi-rule-two-resources",
		Rules: []*types.PolicyRule{
			{
				Enabled:      true,
				Sources:      []string{s.sourceGroupID},
				Destinations: []string{s.resourceGroupID},
				Action:       types.PolicyTrafficActionAccept,
			},
			{
				Enabled:      true,
				Sources:      []string{s.sourceGroupID},
				Destinations: []string{second.resourceGroupID},
				Action:       types.PolicyTrafficActionAccept,
			},
		},
	}

	affected := s.resolvePolicyAffected(ctx, policy)

	assert.Contains(t, affected, s.routerPeerID, "routing peer for resource A must be affected")
	assert.Contains(t, affected, second.routerPeerID, "routing peer for resource B must be affected")
}

func TestAffectedPeers_RouterOtherNetwork(t *testing.T) {
	s := setupRouterScenario(t, true)
	second := s.addSecondTopology(t, "d")
	ctx := context.Background()

	affected := s.resolvePolicyAffected(ctx, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID))

	assert.Contains(t, affected, s.routerPeerID, "network A's routing peer must be affected")
	assert.NotContains(t, affected, second.routerPeerID,
		"a router in an unrelated network must not be affected by a policy that does not target its resource")
}
