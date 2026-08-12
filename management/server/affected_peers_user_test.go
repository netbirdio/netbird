package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// A user update refreshes only the peers its auto-group change reaches, and a user
// update that changes no group membership refreshes nobody.
func TestAffectedPeers_SaveUser_OnlyAffectedPeersUpdated(t *testing.T) {
	manager, updateManager, account, _, peer2, peer3 := setupNetworkMapTest(t)
	ctx := context.Background()
	accountID := account.Id

	const targetUserID = "target-user"
	require.NoError(t, manager.Store.SaveUser(ctx, &types.User{
		Id: targetUserID, AccountID: accountID, Role: types.UserRoleUser,
	}))

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	targetPeer, _, _, _, err := manager.AddPeer(ctx, accountID, "", targetUserID, &nbpeer.Peer{
		Key:  key.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "target-peer"},
	}, false)
	require.NoError(t, err)

	policies, err := manager.Store.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)
	for _, p := range policies {
		require.NoError(t, manager.Store.DeletePolicy(ctx, accountID, p.ID))
	}

	account, err = manager.Store.GetAccount(ctx, accountID)
	require.NoError(t, err)
	account.Settings.GroupsPropagationEnabled = true
	require.NoError(t, manager.Store.SaveAccount(ctx, account))

	require.NoError(t, manager.CreateGroup(ctx, accountID, userID, &types.Group{ID: "ug-linked", Name: "ug-linked"}))
	require.NoError(t, manager.CreateGroup(ctx, accountID, userID, &types.Group{ID: "ug-dest", Name: "ug-dest", Peers: []string{peer2.ID}}))

	_, err = manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{"ug-linked"},
				Destinations:  []string{"ug-dest"},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	updTarget := updateManager.CreateChannel(ctx, targetPeer.ID)
	upd2 := updateManager.CreateChannel(ctx, peer2.ID)
	upd3 := updateManager.CreateChannel(ctx, peer3.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(ctx, targetPeer.ID)
		updateManager.CloseChannel(ctx, peer2.ID)
		updateManager.CloseChannel(ctx, peer3.ID)
	})

	t.Run("auto group change updates only linked peers", func(t *testing.T) {
		drainPeerUpdates(updTarget)
		drainPeerUpdates(upd2)
		drainPeerUpdates(upd3)

		_, err := manager.SaveUser(ctx, accountID, activity.SystemInitiator, &types.User{
			Id: targetUserID, AccountID: accountID, Role: types.UserRoleUser,
			AutoGroups: []string{"ug-linked"},
		})
		require.NoError(t, err)

		peerShouldReceiveUpdate(t, updTarget)
		peerShouldReceiveUpdate(t, upd2)
		peerShouldNotReceiveUpdate(t, upd3)
	})

	t.Run("update without group changes refreshes nobody", func(t *testing.T) {
		drainPeerUpdates(updTarget)
		drainPeerUpdates(upd2)
		drainPeerUpdates(upd3)

		_, err := manager.SaveUser(ctx, accountID, activity.SystemInitiator, &types.User{
			Id: targetUserID, AccountID: accountID, Role: types.UserRoleUser,
			AutoGroups: []string{"ug-linked"}, Name: "renamed",
		})
		require.NoError(t, err)

		peerShouldNotReceiveUpdate(t, updTarget)
		peerShouldNotReceiveUpdate(t, upd2)
		peerShouldNotReceiveUpdate(t, upd3)

		user, err := manager.Store.GetUserByUserID(ctx, store.LockingStrengthNone, targetUserID)
		require.NoError(t, err)
		assert.Equal(t, "renamed", user.Name)
	})

	t.Run("auto group change reassigning IPv6 refreshes the changed peers and their observers", func(t *testing.T) {
		account, err := manager.Store.GetAccount(ctx, accountID)
		require.NoError(t, err)
		account.Settings.IPv6EnabledGroups = []string{"ug-v6"}
		require.NoError(t, manager.Store.SaveAccount(ctx, account))
		require.NoError(t, manager.CreateGroup(ctx, accountID, userID, &types.Group{ID: "ug-v6", Name: "ug-v6"}))

		drainPeerUpdates(updTarget)
		drainPeerUpdates(upd2)
		drainPeerUpdates(upd3)

		_, err = manager.SaveUser(ctx, accountID, activity.SystemInitiator, &types.User{
			Id: targetUserID, AccountID: accountID, Role: types.UserRoleUser,
			AutoGroups: []string{"ug-linked", "ug-v6"}, Name: "renamed",
		})
		require.NoError(t, err)

		// The reassigned peer refreshes with everyone it can reach: peer2 via the
		// policy, but not peer3, which shares no group or policy with it.
		peerShouldReceiveUpdate(t, updTarget)
		peerShouldReceiveUpdate(t, upd2)
		peerShouldNotReceiveUpdate(t, upd3)
	})

	t.Run("unblocking a user refreshes only the SSH rule destinations", func(t *testing.T) {
		// An SSH rule that authorizes no group of its own ships the account's
		// allowed-user set to its destinations, so those are the peers an unblock
		// reaches — not the whole account.
		_, err := manager.SavePolicy(ctx, accountID, userID, &types.Policy{
			Enabled: true,
			Rules: []*types.PolicyRule{{
				Enabled:      true,
				Sources:      []string{"ug-linked"},
				Destinations: []string{"ug-dest"},
				Protocol:     types.PolicyRuleProtocolNetbirdSSH,
				Action:       types.PolicyTrafficActionAccept,
			}},
		}, true)
		require.NoError(t, err)

		blocked, err := manager.Store.GetUserByUserID(ctx, store.LockingStrengthNone, targetUserID)
		require.NoError(t, err)
		blocked.Blocked = true
		require.NoError(t, manager.Store.SaveUser(ctx, blocked))

		drainPeerUpdates(updTarget)
		drainPeerUpdates(upd2)
		drainPeerUpdates(upd3)

		// Same auto-groups as the previous subtest left them, so no group change and
		// no IPv6 reconciliation interferes: the unblock alone drives the refresh.
		_, err = manager.SaveUser(ctx, accountID, activity.SystemInitiator, &types.User{
			Id: targetUserID, AccountID: accountID, Role: types.UserRoleUser,
			AutoGroups: []string{"ug-linked", "ug-v6"}, Name: "renamed",
		})
		require.NoError(t, err)

		peerShouldReceiveUpdate(t, upd2)
		peerShouldNotReceiveUpdate(t, upd3)
	})
}
