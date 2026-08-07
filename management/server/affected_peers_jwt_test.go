package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

// TestAffectedPeers_SyncUserJWTGroups_OnlyAffectedPeersUpdated verifies that a JWT
// auto-group change updates only the user's peers and the peers linked to the changed
// group through policies, instead of fanning out to the whole account.
func TestAffectedPeers_SyncUserJWTGroups_OnlyAffectedPeersUpdated(t *testing.T) {
	manager, updateManager, account, _, peer2, peer3 := setupNetworkMapTest(t)
	ctx := context.Background()
	accountID := account.Id

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	userPeer, _, _, _, err := manager.AddPeer(ctx, accountID, "", userID, &nbpeer.Peer{
		Key:  key.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "user-peer"},
	}, false)
	require.NoError(t, err)

	policies, err := manager.Store.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)
	for _, p := range policies {
		require.NoError(t, manager.Store.DeletePolicy(ctx, accountID, p.ID))
	}

	account, err = manager.Store.GetAccount(ctx, accountID)
	require.NoError(t, err)
	account.Settings.JWTGroupsEnabled = true
	account.Settings.JWTGroupsClaimName = "groups"
	account.Settings.GroupsPropagationEnabled = true
	require.NoError(t, manager.Store.SaveAccount(ctx, account))

	require.NoError(t, manager.CreateGroup(ctx, accountID, userID, &types.Group{ID: "jwt-grp", Name: "jwt-linked", Issued: types.GroupIssuedJWT, Peers: []string{}}))
	require.NoError(t, manager.CreateGroup(ctx, accountID, userID, &types.Group{ID: "jwt-dest", Name: "jwt-dest", Peers: []string{peer2.ID}}))

	_, err = manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{"jwt-grp"},
				Destinations:  []string{"jwt-dest"},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	updUser := updateManager.CreateChannel(ctx, userPeer.ID)
	upd2 := updateManager.CreateChannel(ctx, peer2.ID)
	upd3 := updateManager.CreateChannel(ctx, peer3.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(ctx, userPeer.ID)
		updateManager.CloseChannel(ctx, peer2.ID)
		updateManager.CloseChannel(ctx, peer3.ID)
	})

	userAuth := auth.UserAuth{
		AccountId: accountID,
		UserId:    userID,
		Groups:    []string{"jwt-linked"},
	}

	t.Run("adding JWT group updates only linked peers", func(t *testing.T) {
		drainPeerUpdates(updUser)
		drainPeerUpdates(upd2)
		drainPeerUpdates(upd3)

		require.NoError(t, manager.SyncUserJWTGroups(ctx, userAuth))

		peerShouldReceiveUpdate(t, updUser)
		peerShouldReceiveUpdate(t, upd2)
		peerShouldNotReceiveUpdate(t, upd3)

		user, err := manager.Store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
		require.NoError(t, err)
		assert.Contains(t, user.AutoGroups, "jwt-grp")
	})

	t.Run("removing JWT group updates only linked peers", func(t *testing.T) {
		drainPeerUpdates(updUser)
		drainPeerUpdates(upd2)
		drainPeerUpdates(upd3)

		userAuth.Groups = nil
		require.NoError(t, manager.SyncUserJWTGroups(ctx, userAuth))

		peerShouldReceiveUpdate(t, updUser)
		peerShouldReceiveUpdate(t, upd2)
		peerShouldNotReceiveUpdate(t, upd3)

		user, err := manager.Store.GetUserByUserID(ctx, store.LockingStrengthNone, userID)
		require.NoError(t, err)
		assert.NotContains(t, user.AutoGroups, "jwt-grp")
	})
}
