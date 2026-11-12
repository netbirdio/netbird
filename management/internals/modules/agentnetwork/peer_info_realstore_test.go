package agentnetwork

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/modules/agentnetwork/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	nbtypes "github.com/netbirdio/netbird/management/server/types"
)

// peerInfoFixture seeds an account where the user's auto-groups and the
// peer's groups deliberately differ: the policy covers grp-eng, the user's
// auto-groups only hold grp-other, and the peer itself sits in grp-eng.
// The proxy authorizes tunnel requests by the peer's groups, so the peer
// answer must list the provider even though the user answer would not.
func peerInfoFixture(t *testing.T, withSettings bool) (*managerImpl, store.Store) {
	t.Helper()
	mgr, s := newAgentConfigTestMgr(t)
	ctx := context.Background()

	require.NoError(t, s.SaveAccount(ctx, &nbtypes.Account{Id: testAccountID}))
	require.NoError(t, s.SaveAccount(ctx, &nbtypes.Account{Id: "acct-other"}))
	for _, g := range []string{"grp-eng", "grp-other"} {
		require.NoError(t, s.CreateGroup(ctx, &nbtypes.Group{ID: g, AccountID: testAccountID, Name: g}))
	}

	if withSettings {
		require.NoError(t, s.SaveAgentNetworkSettings(ctx, newSynthTestSettings()))
	}
	provider := newSynthTestProvider()
	require.NoError(t, s.SaveAgentNetworkProvider(ctx, provider))
	require.NoError(t, s.SaveAgentNetworkPolicy(ctx, newSynthTestPolicy(provider.ID, "grp-eng", "")))

	require.NoError(t, s.SaveUser(ctx, &nbtypes.User{
		Id: "user-1", AccountID: testAccountID, Role: nbtypes.UserRoleUser,
		Email: "user-1@example.com", AutoGroups: []string{"grp-other"},
	}))
	require.NoError(t, s.SaveUser(ctx, &nbtypes.User{
		Id: "user-blocked", AccountID: testAccountID, Role: nbtypes.UserRoleUser, Blocked: true,
	}))
	require.NoError(t, s.SaveUser(ctx, &nbtypes.User{
		Id: "user-foreign", AccountID: "acct-other", Role: nbtypes.UserRoleUser, Email: "foreign@example.com",
	}))

	addPeer := func(id, userID string, octet byte, expired bool, groups ...string) {
		require.NoError(t, s.AddPeerToAccount(ctx, &nbpeer.Peer{
			ID:        id,
			AccountID: testAccountID,
			UserID:    userID,
			Key:       "key-" + id,
			DNSLabel:  id,
			IP:        netip.AddrFrom4([4]byte{100, 64, 0, octet}),
			Status:    &nbpeer.PeerStatus{LoginExpired: expired},
		}))
		for _, g := range groups {
			require.NoError(t, s.AddPeerToGroup(ctx, testAccountID, id, g))
		}
	}
	addPeer("peer-user", "user-1", 1, false, "grp-eng")
	addPeer("peer-expired", "user-1", 2, true, "grp-eng")
	addPeer("peer-setupkey", "", 3, false, "grp-eng")
	addPeer("peer-blocked", "user-blocked", 4, false, "grp-eng")
	addPeer("peer-foreign-owner", "user-foreign", 5, false, "grp-eng")
	addPeer("peer-uncovered", "user-1", 6, false, "grp-other")

	return mgr, s
}

func TestGetAgentNetworkInfoForPeer_RealStore(t *testing.T) {
	mgr, _ := peerInfoFixture(t, true)
	ctx := context.Background()

	t.Run("peer groups decide, not user auto-groups", func(t *testing.T) {
		info, err := mgr.GetAgentNetworkInfoForPeer(ctx, testAccountID, "peer-user")
		require.NoError(t, err)
		assert.Equal(t, types.PeerAgentNetworkOK, info.State)
		require.NotNil(t, info.Config)
		assert.Equal(t, "https://"+testEndpoint, info.Config.Endpoint)
		require.Len(t, info.Config.Providers, 1, "peer is in grp-eng, which the policy covers")
		assert.Equal(t, "prov-1", info.Config.Providers[0].ID)
		assert.Equal(t, "openai_api", info.Config.Providers[0].CatalogID)

		// The same user's auto-groups do not reach the policy.
		userCfg, err := mgr.GetAgentConfigForUser(ctx, testAccountID, "user-1")
		require.NoError(t, err)
		assert.Empty(t, userCfg.Providers, "fixture must make auto-groups and peer groups disagree")
	})

	t.Run("peer outside the policy gets OK with no providers", func(t *testing.T) {
		info, err := mgr.GetAgentNetworkInfoForPeer(ctx, testAccountID, "peer-uncovered")
		require.NoError(t, err)
		assert.Equal(t, types.PeerAgentNetworkOK, info.State)
		require.NotNil(t, info.Config)
		assert.Empty(t, info.Config.Providers, "no policy covers grp-other")
	})

	t.Run("expired login still answers", func(t *testing.T) {
		info, err := mgr.GetAgentNetworkInfoForPeer(ctx, testAccountID, "peer-expired")
		require.NoError(t, err)
		assert.Equal(t, types.PeerAgentNetworkOK, info.State)
		require.NotNil(t, info.Config)
		assert.Len(t, info.Config.Providers, 1, "expired peers still see their providers")
	})

	t.Run("setup-key peer has no user", func(t *testing.T) {
		info, err := mgr.GetAgentNetworkInfoForPeer(ctx, testAccountID, "peer-setupkey")
		require.NoError(t, err)
		assert.Equal(t, types.PeerAgentNetworkNoUser, info.State)
		assert.Nil(t, info.Config, "no providers for a peer without a user")
	})

	t.Run("blocked owner", func(t *testing.T) {
		info, err := mgr.GetAgentNetworkInfoForPeer(ctx, testAccountID, "peer-blocked")
		require.NoError(t, err)
		assert.Equal(t, types.PeerAgentNetworkUserBlocked, info.State)
		assert.Nil(t, info.Config, "blocked owner must not see providers")
	})

	t.Run("owner from another account is refused", func(t *testing.T) {
		info, err := mgr.GetAgentNetworkInfoForPeer(ctx, testAccountID, "peer-foreign-owner")
		require.Error(t, err)
		assert.Nil(t, info, "must never answer with another account's user")
	})

	t.Run("peer from another account is not found", func(t *testing.T) {
		_, err := mgr.GetAgentNetworkInfoForPeer(ctx, "acct-other", "peer-user")
		require.Error(t, err)
	})
}

func TestGetAgentNetworkInfoForPeer_RealStore_NotEnabled(t *testing.T) {
	mgr, _ := peerInfoFixture(t, false)

	info, err := mgr.GetAgentNetworkInfoForPeer(context.Background(), testAccountID, "peer-user")
	require.NoError(t, err)
	assert.Equal(t, types.PeerAgentNetworkNotEnabled, info.State)
	assert.Nil(t, info.Config, "no config without an Agent Network")
}
