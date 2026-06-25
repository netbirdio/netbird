package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/affectedpeers"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
)

func (s *routerScenario) resolveGroupChangeAffected(ctx context.Context, changedGroupIDs []string) []string {
	change := affectedpeers.Change{ChangedGroupIDs: changedGroupIDs}
	snap, err := affectedpeers.Load(ctx, s.manager.Store, s.accountID, change)
	if err != nil {
		return nil
	}
	return snap.Expand(ctx, s.accountID, change)
}

func (s *routerScenario) resolvePeerChangeAffected(ctx context.Context, changedPeerIDs []string) []string {
	change := affectedpeers.Change{ChangedPeerIDs: changedPeerIDs}
	snap, err := affectedpeers.Load(ctx, s.manager.Store, s.accountID, change)
	if err != nil {
		return nil
	}
	return snap.Expand(ctx, s.accountID, change)
}

func TestAffectedPeers_GroupChange_SourceGroupMembership_RefreshesRoutingPeer_DirectRouter(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
	require.NoError(t, err)

	affected := s.resolveGroupChangeAffected(ctx, []string{s.sourceGroupID})

	assert.Contains(t, affected, s.sourcePeerID, "source group member must be affected")
	assert.Contains(t, affected, s.routerPeerID,
		"changing the source group of a peer->resource policy must refresh the resource's routing peer")
	assert.NotContains(t, affected, s.unrelatedPeerID, "unrelated peer must not be affected")
}

func TestAffectedPeers_GroupChange_SourceGroupMembership_RefreshesRoutingPeer_RouterPeerGroups(t *testing.T) {
	s := setupRouterScenario(t, false)
	ctx := context.Background()

	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
	require.NoError(t, err)

	affected := s.resolveGroupChangeAffected(ctx, []string{s.sourceGroupID})

	assert.Contains(t, affected, s.routerGroupPeerID,
		"changing the source group must refresh the routing peer defined via router.PeerGroups")
	assert.NotContains(t, affected, s.unrelatedPeerID, "unrelated peer must not be affected")
}

func TestAffectedPeers_GroupChange_RouterPeerGroupMembership_RefreshesPolicySources(t *testing.T) {
	s := setupRouterScenario(t, false)
	ctx := context.Background()

	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
	require.NoError(t, err)

	affected := s.resolveGroupChangeAffected(ctx, []string{s.routerPeerGroupID})

	assert.Contains(t, affected, s.routerGroupPeerID, "the routing peer itself must be affected")
	assert.Contains(t, affected, s.sourcePeerID,
		"changing the router's PeerGroups must refresh the source peers of policies serving the resource")
	assert.NotContains(t, affected, s.unrelatedPeerID, "unrelated peer must not be affected")
}

func TestAffectedPeers_PeerChange_SourcePeer_RefreshesRoutingPeer(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
	require.NoError(t, err)

	affected := s.resolvePeerChangeAffected(ctx, []string{s.sourcePeerID})

	assert.Contains(t, affected, s.routerPeerID,
		"a status change on a source peer must refresh the resource's routing peer that serves it")
	assert.NotContains(t, affected, s.unrelatedPeerID, "unrelated peer must not be affected")
}

func TestAffectedPeers_PeerChange_SourcePeer_ByDestinationResource_RefreshesRoutingPeer(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByResource(s.sourceGroupID, s.resourceID), true)
	require.NoError(t, err)

	affected := s.resolvePeerChangeAffected(ctx, []string{s.sourcePeerID})

	assert.Contains(t, affected, s.routerPeerID,
		"DestinationResource-targeted policy must still bridge a source-peer change to the routing peer")
	assert.NotContains(t, affected, s.unrelatedPeerID, "unrelated peer must not be affected")
}

func TestAffectedPeers_E2E_DeleteGroup_ResolvesAffectedPeers(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	const memberOnlyGroupID = "rs-memberonly-grp"
	require.NoError(t, s.manager.CreateGroup(ctx, s.accountID, userID, &types.Group{
		ID: memberOnlyGroupID, Name: "rs-memberonly", Peers: []string{s.sourcePeerID},
	}))

	affected := s.resolveGroupChangeAffected(ctx, []string{memberOnlyGroupID})
	assert.Empty(t, affected, "an unlinked group has no network-map impact, so no peer is affected")

	require.NoError(t, s.manager.DeleteGroup(ctx, s.accountID, userID, memberOnlyGroupID))
}

func TestAffectedPeers_GroupAddResource_RefreshesRoutingPeer(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	const extraResourceGroupID = "rs-resource-grp-extra"
	require.NoError(t, s.manager.CreateGroup(ctx, s.accountID, userID, &types.Group{
		ID: extraResourceGroupID, Name: "rs-resource-extra",
	}))

	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, extraResourceGroupID), true)
	require.NoError(t, err)

	require.NoError(t, s.manager.GroupAddResource(ctx, s.accountID, extraResourceGroupID, types.Resource{
		ID:   s.resourceID,
		Type: types.ResourceTypeHost,
	}))

	affected := s.resolveGroupChangeAffected(ctx, []string{extraResourceGroupID})

	assert.Contains(t, affected, s.routerPeerID,
		"attaching a resource to a policy destination group must refresh the resource's routing peer")
	assert.Contains(t, affected, s.sourcePeerID, "policy source peers must refresh")
	assert.NotContains(t, affected, s.unrelatedPeerID, "unrelated peer must not be affected")
}

func (s *routerScenario) createPostureCheckGatedPolicy(t *testing.T, ctx context.Context) string {
	t.Helper()

	check, err := s.manager.SavePostureChecks(ctx, s.accountID, userID, &posture.Checks{
		Name: "rs-min-version",
		Checks: posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{MinVersion: "0.30.0"},
		},
	}, true)
	require.NoError(t, err)

	policy := peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID)
	policy.SourcePostureChecks = []string{check.ID}
	_, err = s.manager.SavePolicy(ctx, s.accountID, userID, policy, true)
	require.NoError(t, err)

	return check.ID
}

func TestAffectedPeers_E2E_SavePostureCheck_RefreshesRoutingPeer(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	checkID := s.createPostureCheckGatedPolicy(t, ctx)

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

	_, err := s.manager.SavePostureChecks(ctx, s.accountID, userID, &posture.Checks{
		ID:   checkID,
		Name: "rs-min-version",
		Checks: posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{MinVersion: "0.31.0"},
		},
	}, false)
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(peerUpdateTimeout):
		t.Error("timeout: editing a posture check did not refresh source + routing peers")
	}
}

func TestAffectedPeers_E2E_UpdateResource_DestinationResourcePolicy_RefreshesSourcePeer(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByResource(s.sourceGroupID, s.resourceID), true)
	require.NoError(t, err)

	resourcesManager, _, _ := s.managers()

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

	_, err = resourcesManager.UpdateResource(ctx, userID, &resourceTypes.NetworkResource{
		ID:        s.resourceID,
		AccountID: s.accountID,
		NetworkID: s.networkID,
		Name:      "rs-resource-host",
		Address:   "10.20.30.0/25",
		GroupIDs:  []string{s.resourceGroupID},
		Enabled:   true,
	})
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(peerUpdateTimeout):
		t.Error("timeout: updating a DestinationResource-targeted resource did not refresh its policy source peer")
	}
}

// A disabled sibling router routes to nobody, so updating a resource on its network
// must NOT refresh its peer (the enabled router carries the bridge instead).
func TestAffectedPeers_E2E_UpdateResource_DisabledSiblingRouterNotBridged(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
	require.NoError(t, err)

	resourcesManager, routersManager, _ := s.managers()

	setupKey, err := s.manager.CreateSetupKey(ctx, s.accountID, "rs-key-disabled", types.SetupKeyReusable, time.Hour, nil, 999, userID, false, false)
	require.NoError(t, err)
	disabledRouterPeer := addPeerToAccount(t, s.manager, s.accountID, setupKey.Key)
	_, err = routersManager.CreateRouter(ctx, userID, &routerTypes.NetworkRouter{
		NetworkID:  s.networkID,
		AccountID:  s.accountID,
		Peer:       disabledRouterPeer.ID,
		Masquerade: true,
		Metric:     9000,
		Enabled:    false,
	})
	require.NoError(t, err)

	disabledCh := s.updateManager.CreateChannel(ctx, disabledRouterPeer.ID)
	enabledCh := s.updateManager.CreateChannel(ctx, s.routerPeerID)
	t.Cleanup(func() {
		s.updateManager.CloseChannel(ctx, disabledRouterPeer.ID)
		s.updateManager.CloseChannel(ctx, s.routerPeerID)
	})

	settleAffectedUpdates(disabledCh, enabledCh)

	done := make(chan struct{})
	go func() {
		peerShouldReceiveUpdate(t, enabledCh)
		peerShouldNotReceiveUpdate(t, disabledCh)
		close(done)
	}()

	_, err = resourcesManager.UpdateResource(ctx, userID, &resourceTypes.NetworkResource{
		ID:        s.resourceID,
		AccountID: s.accountID,
		NetworkID: s.networkID,
		Name:      "rs-resource-host",
		Address:   "10.20.30.0/25",
		GroupIDs:  []string{s.resourceGroupID},
		Enabled:   true,
	})
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(peerUpdateTimeout):
		t.Error("timeout")
	}
}

func TestAffectedPeers_GroupChange_RouterInOtherNetworkNotAffected(t *testing.T) {
	s := setupRouterScenario(t, true)
	second := s.addSecondTopology(t, "groupiso")
	ctx := context.Background()

	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
	require.NoError(t, err)

	affected := s.resolveGroupChangeAffected(ctx, []string{s.sourceGroupID})

	assert.Contains(t, affected, s.routerPeerID, "network A's routing peer must be affected")
	assert.NotContains(t, affected, second.routerPeerID,
		"a router in an unrelated network must not be affected by a source-group change for another resource")
}

func TestAffectedPeers_PeerChange_RouterInOtherNetworkNotAffected(t *testing.T) {
	s := setupRouterScenario(t, true)
	second := s.addSecondTopology(t, "peeriso")
	ctx := context.Background()

	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
	require.NoError(t, err)

	affected := s.resolvePeerChangeAffected(ctx, []string{s.sourcePeerID})

	assert.Contains(t, affected, s.routerPeerID, "network A's routing peer must be affected")
	assert.NotContains(t, affected, second.routerPeerID,
		"a router in an unrelated network must not be affected by a source-peer change for another resource")
}
