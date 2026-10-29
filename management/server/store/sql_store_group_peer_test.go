package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
)

func TestSqlStore_AddPeerToGroup(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_policy_migrate.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	peerID := "cfefqs706sqkneg59g4g"
	groupID := "cfefqs706sqkneg59g4h"

	group, err := store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, groupID)
	require.NoError(t, err, "failed to get group")
	require.Len(t, group.Peers, 0, "group should have 0 peers")

	err = store.AddPeerToGroup(context.Background(), accountID, peerID, groupID)
	require.NoError(t, err, "failed to add peer to group")

	group, err = store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, groupID)
	require.NoError(t, err, "failed to get group")
	require.Len(t, group.Peers, 1, "group should have 1 peers")
	require.Contains(t, group.Peers, peerID)
}

func TestSqlStore_AddPeerToAllGroup(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_policy_migrate.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	groupID := "cfefqs706sqkneg59g3g"

	peer := &nbpeer.Peer{
		ID:        "peer1",
		AccountID: accountID,
		DNSLabel:  "peer1.domain.test",
	}

	group, err := store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, groupID)
	require.NoError(t, err, "failed to get group")
	require.Len(t, group.Peers, 2, "group should have 2 peers")
	require.NotContains(t, group.Peers, peer.ID)

	err = store.AddPeerToAccount(context.Background(), peer)
	require.NoError(t, err, "failed to add peer to account")

	err = store.AddPeerToAllGroup(context.Background(), accountID, peer.ID)
	require.NoError(t, err, "failed to add peer to all group")

	group, err = store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, groupID)
	require.NoError(t, err, "failed to get group")
	require.Len(t, group.Peers, 3, "group should have  peers")
	require.Contains(t, group.Peers, peer.ID)
}

func TestSqlStore_GetPeerGroups(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_policy_migrate.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	peerID := "cfefqs706sqkneg59g4g"

	groups, err := store.GetPeerGroups(context.Background(), LockingStrengthNone, accountID, peerID)
	require.NoError(t, err)
	assert.Len(t, groups, 1)
	assert.Equal(t, groups[0].Name, "All")

	err = store.AddPeerToGroup(context.Background(), accountID, peerID, "cfefqs706sqkneg59g4h")
	require.NoError(t, err)

	groups, err = store.GetPeerGroups(context.Background(), LockingStrengthNone, accountID, peerID)
	require.NoError(t, err)
	assert.Len(t, groups, 2)

	foreignPeerID := "foreign-peer"
	err = store.AddPeerToGroup(context.Background(), accountID, foreignPeerID, "cfefqs706sqkneg59g4h")
	require.NoError(t, err)

	groups, err = store.GetPeerGroups(context.Background(), LockingStrengthNone, "other-account", foreignPeerID)
	require.NoError(t, err)
	assert.Empty(t, groups, "groups of another account must not be returned")
}

func TestSqlStore_GetPeersByGroupIDs(t *testing.T) {
	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	group1ID := "test-group-1"
	group2ID := "test-group-2"
	emptyGroupID := "empty-group"

	peer1 := "cfefqs706sqkneg59g4g"
	peer2 := "cfeg6sf06sqkneg59g50"

	tests := []struct {
		name          string
		groupIDs      []string
		expectedPeers []string
		expectedCount int
	}{
		{
			name:          "retrieve peers from single group with multiple peers",
			groupIDs:      []string{group1ID},
			expectedPeers: []string{peer1, peer2},
			expectedCount: 2,
		},
		{
			name:          "retrieve peers from single group with one peer",
			groupIDs:      []string{group2ID},
			expectedPeers: []string{peer1},
			expectedCount: 1,
		},
		{
			name:          "retrieve peers from multiple groups (with overlap)",
			groupIDs:      []string{group1ID, group2ID},
			expectedPeers: []string{peer1, peer2}, // should deduplicate
			expectedCount: 2,
		},
		{
			name:          "retrieve peers from existing 'All' group",
			groupIDs:      []string{"cfefqs706sqkneg59g3g"}, // All group from test data
			expectedPeers: []string{peer1, peer2},
			expectedCount: 2,
		},
		{
			name:          "retrieve peers from empty group",
			groupIDs:      []string{emptyGroupID},
			expectedPeers: []string{},
			expectedCount: 0,
		},
		{
			name:          "retrieve peers from non-existing group",
			groupIDs:      []string{"non-existing-group"},
			expectedPeers: []string{},
			expectedCount: 0,
		},
		{
			name:          "empty group IDs list",
			groupIDs:      []string{},
			expectedPeers: []string{},
			expectedCount: 0,
		},
		{
			name:          "mix of existing and non-existing groups",
			groupIDs:      []string{group1ID, "non-existing-group"},
			expectedPeers: []string{peer1, peer2},
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store_policy_migrate.sql", t.TempDir())
			t.Cleanup(cleanup)
			require.NoError(t, err)

			ctx := context.Background()

			groups := []*types.Group{
				{
					ID:        group1ID,
					AccountID: accountID,
				},
				{
					ID:        group2ID,
					AccountID: accountID,
				},
			}
			require.NoError(t, store.CreateGroups(ctx, accountID, groups))

			otherAccount := newAccountWithId(ctx, "other-account", "other-user", "")
			require.NoError(t, store.SaveAccount(ctx, otherAccount))
			foreignPeer := &nbpeer.Peer{ID: "foreign-peer", AccountID: otherAccount.Id}
			require.NoError(t, store.AddPeerToAccount(ctx, foreignPeer))

			require.NoError(t, store.AddPeerToGroup(ctx, accountID, peer1, group1ID))
			require.NoError(t, store.AddPeerToGroup(ctx, accountID, peer2, group1ID))
			require.NoError(t, store.AddPeerToGroup(ctx, accountID, peer1, group2ID))
			require.NoError(t, store.AddPeerToGroup(ctx, accountID, foreignPeer.ID, group1ID))

			peers, err := store.GetPeersByGroupIDs(ctx, accountID, tt.groupIDs)
			require.NoError(t, err)
			require.Len(t, peers, tt.expectedCount)

			if tt.expectedCount > 0 {
				actualPeerIDs := make([]string, len(peers))
				for i, peer := range peers {
					actualPeerIDs[i] = peer.ID
				}
				assert.ElementsMatch(t, tt.expectedPeers, actualPeerIDs)

				// Verify all returned peers belong to the correct account
				for _, peer := range peers {
					assert.Equal(t, accountID, peer.AccountID)
				}
			}
		})
	}
}
