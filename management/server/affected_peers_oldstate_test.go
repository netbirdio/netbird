package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// An update spans an old and a new state. The affected set must be the UNION of
// peers reachable before and after the change; resolving only against the final
// state drops peers that were reachable but no longer are. These tests pin the
// two paths where the old state is reachable only by the changed object's
// previous references: detaching a resource group, and re-pointing a router peer.

// TestAffectedPeers_E2E_UpdateResource_DetachGroup_RefreshesOldGroupSources:
// a resource is reachable by a source group via two destination resource groups;
// detaching one of them must still refresh that group's policy source peers, even
// though the post-update resource no longer maps to it.
func TestAffectedPeers_E2E_UpdateResource_DetachGroup_RefreshesOldGroupSources(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	// A second resource group + a second source group/peer that reaches the
	// resource only through that second group.
	const detachGroupID = "rs-detach-grp"
	require.NoError(t, s.manager.CreateGroup(ctx, s.accountID, userID, &types.Group{ID: detachGroupID, Name: "rs-detach"}))

	const secondSourceGroupID = "rs-source-grp-2"
	setupKey, err := s.manager.CreateSetupKey(ctx, s.accountID, "rs-detach-key", types.SetupKeyReusable, time.Hour, nil, 999, userID, false, false)
	require.NoError(t, err)
	secondSourcePeer := addPeerToAccount(t, s.manager, s.accountID, setupKey.Key)
	require.NoError(t, s.manager.CreateGroup(ctx, s.accountID, userID, &types.Group{
		ID: secondSourceGroupID, Name: "rs-source-2", Peers: []string{secondSourcePeer.ID},
	}))

	resourcesManager, _, _ := s.managers()

	// Attach the resource to the detach group as well: now in [resourceGroup, detachGroup].
	_, err = resourcesManager.UpdateResource(ctx, userID, &resourceTypes.NetworkResource{
		ID:        s.resourceID,
		AccountID: s.accountID,
		NetworkID: s.networkID,
		Name:      "rs-resource-host",
		Address:   "10.20.30.0/24",
		GroupIDs:  []string{s.resourceGroupID, detachGroupID},
		Enabled:   true,
	})
	require.NoError(t, err)

	// Policy granting the second source group access via the detach group.
	_, err = s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(secondSourceGroupID, detachGroupID), true)
	require.NoError(t, err)

	secondSrcCh := s.updateManager.CreateChannel(ctx, secondSourcePeer.ID)
	t.Cleanup(func() { s.updateManager.CloseChannel(ctx, secondSourcePeer.ID) })
	settleAffectedUpdates(secondSrcCh)

	done := make(chan struct{})
	go func() {
		// Detaching the resource from detachGroup removes the second source's
		// access; that source peer must be refreshed even though the post-update
		// resource no longer maps to detachGroup.
		peerShouldReceiveUpdate(t, secondSrcCh)
		close(done)
	}()

	_, err = resourcesManager.UpdateResource(ctx, userID, &resourceTypes.NetworkResource{
		ID:        s.resourceID,
		AccountID: s.accountID,
		NetworkID: s.networkID,
		Name:      "rs-resource-host",
		Address:   "10.20.30.0/24",
		GroupIDs:  []string{s.resourceGroupID}, // detached detachGroup
		Enabled:   true,
	})
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(peerUpdateTimeout):
		t.Error("timeout: detaching a resource group did not refresh the old group's policy source peer")
	}
}

// TestAffectedPeers_E2E_UpdateRouter_RepointPeer_RefreshesOldRoutingPeer:
// changing router.Peer within the same network must still refresh the OLD routing
// peer, which loses its routing role.
func TestAffectedPeers_E2E_UpdateRouter_RepointPeer_RefreshesOldRoutingPeer(t *testing.T) {
	s := setupRouterScenario(t, true)
	ctx := context.Background()

	_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
	require.NoError(t, err)

	_, routersManager, _ := s.managers()

	routers, err := s.manager.Store.GetNetworkRoutersByNetID(ctx, store.LockingStrengthNone, s.accountID, s.networkID)
	require.NoError(t, err)
	require.Len(t, routers, 1)
	router := routers[0]
	oldRoutingPeer := router.Peer
	require.NotEmpty(t, oldRoutingPeer)

	// A new peer to become the routing peer in place of the old one.
	setupKey, err := s.manager.CreateSetupKey(ctx, s.accountID, "rs-newrouter-key", types.SetupKeyReusable, time.Hour, nil, 999, userID, false, false)
	require.NoError(t, err)
	newRoutingPeer := addPeerToAccount(t, s.manager, s.accountID, setupKey.Key)

	oldCh := s.updateManager.CreateChannel(ctx, oldRoutingPeer)
	t.Cleanup(func() { s.updateManager.CloseChannel(ctx, oldRoutingPeer) })
	settleAffectedUpdates(oldCh)

	done := make(chan struct{})
	go func() {
		// The old routing peer stops serving the resource and must be refreshed.
		peerShouldReceiveUpdate(t, oldCh)
		close(done)
	}()

	_, err = routersManager.UpdateRouter(ctx, userID, &routerTypes.NetworkRouter{
		ID:         router.ID,
		NetworkID:  s.networkID,
		AccountID:  s.accountID,
		Peer:       newRoutingPeer.ID, // repoint within the same network
		Masquerade: true,
		Metric:     9999,
		Enabled:    true,
	})
	require.NoError(t, err)

	select {
	case <-done:
	case <-time.After(peerUpdateTimeout):
		t.Error("timeout: re-pointing the router peer did not refresh the old routing peer")
	}
}
