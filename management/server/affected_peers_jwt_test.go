package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/management/server/affectedpeers"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

// A user's auto-group change refreshes the destinations of the SSH rules authorizing
// that group — they carry the group -> user mapping — even though no peer moved
// between groups.
func TestAffectedPeers_UserGroupChange_RefreshesSSHAuthorizedDestinations(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	_, err := manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:          true,
				Sources:          []string{groupIDs[0]},
				Destinations:     []string{groupIDs[1]},
				Protocol:         types.PolicyRuleProtocolNetbirdSSH,
				Action:           types.PolicyTrafficActionAccept,
				AuthorizedGroups: map[string][]string{groupIDs[3]: {"root"}},
			},
		},
	}, true)
	require.NoError(t, err)

	result := resolveAffected(t, s, accountID, affectedpeers.Change{UserGroupIDs: []string{groupIDs[3]}})
	assert.ElementsMatch(t, []string{peerIDs[1]}, result,
		"only the SSH rule's destination peers carry the changed group -> user mapping")

	result = resolveAffected(t, s, accountID, affectedpeers.Change{UserGroupIDs: []string{groupIDs[4]}})
	assert.Empty(t, result, "a group no SSH rule authorizes affects nobody")
}

// Creating, blocking or unblocking a user changes the account's allowed-user set, which
// reaches only the destinations of the SSH rules that ship it.
func TestAffectedPeers_AllowedUsersChange_RefreshesSSHDestinations(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Ships the allowed-user set: an SSH rule naming no groups and no user.
	_, err := manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{{
			Enabled:      true,
			Sources:      []string{groupIDs[0]},
			Destinations: []string{groupIDs[1]},
			Protocol:     types.PolicyRuleProtocolNetbirdSSH,
			Action:       types.PolicyTrafficActionAccept,
		}},
	}, true)
	require.NoError(t, err)

	// Does not ship it: an SSH rule that authorizes a specific group.
	_, err = manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{{
			Enabled:          true,
			Sources:          []string{groupIDs[2]},
			Destinations:     []string{groupIDs[3]},
			Protocol:         types.PolicyRuleProtocolNetbirdSSH,
			Action:           types.PolicyTrafficActionAccept,
			AuthorizedGroups: map[string][]string{groupIDs[0]: {"root"}},
		}},
	}, true)
	require.NoError(t, err)

	result := resolveAffected(t, s, accountID, affectedpeers.Change{AllowedUsersChanged: true})
	assert.ElementsMatch(t, []string{peerIDs[1]}, result,
		"only the destinations of the rule shipping the allowed-user set refresh")
}

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
