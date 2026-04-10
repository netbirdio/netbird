package server

import (
	"context"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// TestGroupIPv6Assignment verifies that peers gain or lose IPv6 addresses
// when they are added to or removed from an IPv6-enabled group.
func TestGroupIPv6Assignment(t *testing.T) {
	am, _, err := createManager(t)
	require.NoError(t, err)

	ctx := context.Background()
	userID := groupAdminUserID

	account, err := createAccount(am, "ipv6-grp-test", userID, "ipv6test.example.com")
	require.NoError(t, err)

	// Allocate IPv6 subnet for the account
	account.Network.NetV6 = types.AllocateIPv6Subnet(rand.New(rand.NewSource(time.Now().UnixNano())))
	require.NoError(t, am.Store.SaveAccount(ctx, account))

	// Create setup key
	setupKey, err := am.CreateSetupKey(ctx, account.Id, "ipv6-key", types.SetupKeyReusable, time.Hour, nil, 999, userID, false, false)
	require.NoError(t, err)

	// Create an IPv6-enabled group
	ipv6GroupID := "ipv6-enabled-grp"
	err = am.CreateGroup(ctx, account.Id, userID, &types.Group{
		ID:     ipv6GroupID,
		Name:   "IPv6 Enabled",
		Issued: types.GroupIssuedAPI,
		Peers:  []string{},
	})
	require.NoError(t, err)

	// Enable IPv6 on that group
	settings, err := am.Store.GetAccountSettings(ctx, store.LockingStrengthNone, account.Id)
	require.NoError(t, err)
	settings.IPv6EnabledGroups = []string{ipv6GroupID}
	require.NoError(t, am.Store.SaveAccountSettings(ctx, account.Id, settings))

	// Register a peer (will be in "All" group, not the IPv6 group)
	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	peer, _, _, err := am.AddPeer(ctx, "", setupKey.Key, "", &nbpeer.Peer{
		Key:  key.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: "ipv6-test-host"},
	}, false)
	require.NoError(t, err)
	assert.False(t, peer.IPv6.IsValid(), "peer should not have IPv6 before joining an IPv6-enabled group")

	t.Run("GroupAddPeer assigns IPv6", func(t *testing.T) {
		err := am.GroupAddPeer(ctx, account.Id, ipv6GroupID, peer.ID)
		require.NoError(t, err)

		p, err := am.Store.GetPeerByID(ctx, store.LockingStrengthNone, account.Id, peer.ID)
		require.NoError(t, err)
		assert.True(t, p.IPv6.IsValid(), "peer should have an IPv6 address after joining the group")
	})

	t.Run("GroupDeletePeer clears IPv6", func(t *testing.T) {
		err := am.GroupDeletePeer(ctx, account.Id, ipv6GroupID, peer.ID)
		require.NoError(t, err)

		p, err := am.Store.GetPeerByID(ctx, store.LockingStrengthNone, account.Id, peer.ID)
		require.NoError(t, err)
		assert.False(t, p.IPv6.IsValid(), "peer should not have IPv6 after removal from the group")
	})

	t.Run("UpdateGroup with peer addition assigns IPv6", func(t *testing.T) {
		grp, err := am.Store.GetGroupByID(ctx, store.LockingStrengthNone, account.Id, ipv6GroupID)
		require.NoError(t, err)

		grp.Peers = append(grp.Peers, peer.ID)
		err = am.UpdateGroup(ctx, account.Id, userID, grp)
		require.NoError(t, err)

		p, err := am.Store.GetPeerByID(ctx, store.LockingStrengthNone, account.Id, peer.ID)
		require.NoError(t, err)
		assert.True(t, p.IPv6.IsValid(), "peer should have IPv6 after UpdateGroup adds it")
	})

	t.Run("UpdateGroup with peer removal clears IPv6", func(t *testing.T) {
		grp, err := am.Store.GetGroupByID(ctx, store.LockingStrengthNone, account.Id, ipv6GroupID)
		require.NoError(t, err)

		grp.Peers = []string{}
		err = am.UpdateGroup(ctx, account.Id, userID, grp)
		require.NoError(t, err)

		p, err := am.Store.GetPeerByID(ctx, store.LockingStrengthNone, account.Id, peer.ID)
		require.NoError(t, err)
		assert.False(t, p.IPv6.IsValid(), "peer should lose IPv6 after UpdateGroup removes it")
	})

	t.Run("non-IPv6 group changes do not affect IPv6", func(t *testing.T) {
		err := am.CreateGroup(ctx, account.Id, userID, &types.Group{
			ID:     "regular-grp",
			Name:   "Regular Group",
			Issued: types.GroupIssuedAPI,
			Peers:  []string{},
		})
		require.NoError(t, err)

		err = am.GroupAddPeer(ctx, account.Id, "regular-grp", peer.ID)
		require.NoError(t, err)

		p, err := am.Store.GetPeerByID(ctx, store.LockingStrengthNone, account.Id, peer.ID)
		require.NoError(t, err)
		assert.False(t, p.IPv6.IsValid(), "peer should not get IPv6 from a non-IPv6 group")
	})
}
