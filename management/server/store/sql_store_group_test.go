package store

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

func TestSqlite_GetGroupByName(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	if err != nil {
		t.Fatal(err)
	}
	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	group, err := store.GetGroupByName(context.Background(), LockingStrengthNone, accountID, "All")
	require.NoError(t, err)
	require.True(t, group.IsGroupAll())
}

func TestSqlStore_GetGroupsByIDs(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	tests := []struct {
		name          string
		groupIDs      []string
		expectedCount int
	}{
		{
			name:          "retrieve existing groups by existing IDs",
			groupIDs:      []string{"cfefqs706sqkneg59g4g", "cfefqs706sqkneg59g3g"},
			expectedCount: 2,
		},
		{
			name:          "empty group IDs list",
			groupIDs:      []string{},
			expectedCount: 0,
		},
		{
			name:          "non-existing group IDs",
			groupIDs:      []string{"nonexistent1", "nonexistent2"},
			expectedCount: 0,
		},
		{
			name:          "mixed existing and non-existing group IDs",
			groupIDs:      []string{"cfefqs706sqkneg59g4g", "nonexistent"},
			expectedCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groups, err := store.GetGroupsByIDs(context.Background(), LockingStrengthNone, accountID, tt.groupIDs)
			require.NoError(t, err)
			require.Len(t, groups, tt.expectedCount)
		})
	}
}

func TestSqlStore_CreateGroup(t *testing.T) {
	if os.Getenv("CI") == "true" {
		t.Log("Skipping MySQL test on CI")
	}
	t.Setenv("NETBIRD_STORE_ENGINE", string(types.MysqlStoreEngine))
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	group := &types.Group{
		ID:         "group-id",
		AccountID:  accountID,
		Issued:     "api",
		Peers:      []string{},
		Resources:  []types.Resource{},
		GroupPeers: []types.GroupPeer{},
	}
	err = store.CreateGroup(context.Background(), group)
	require.NoError(t, err)

	savedGroup, err := store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, "group-id")
	require.NoError(t, err)
	require.Equal(t, savedGroup, group)
}

func TestSqlStore_CreateUpdateGroups(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	groups := []*types.Group{
		{
			ID:         "group-1",
			AccountID:  accountID,
			Issued:     "api",
			Peers:      []string{},
			Resources:  []types.Resource{},
			GroupPeers: []types.GroupPeer{},
		},
		{
			ID:         "group-2",
			AccountID:  accountID,
			Issued:     "integration",
			Peers:      []string{},
			Resources:  []types.Resource{},
			GroupPeers: []types.GroupPeer{},
		},
	}
	err = store.CreateGroups(context.Background(), accountID, groups)
	require.NoError(t, err)

	groups[1].Peers = []string{}
	err = store.UpdateGroups(context.Background(), accountID, groups)
	require.NoError(t, err)

	group, err := store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, groups[1].ID)
	require.NoError(t, err)
	require.Equal(t, groups[1], group)
}

func TestSqlStore_DeleteGroup(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	tests := []struct {
		name        string
		groupID     string
		expectError bool
	}{
		{
			name:        "delete existing group",
			groupID:     "cfefqs706sqkneg59g4g",
			expectError: false,
		},
		{
			name:        "delete non-existing group",
			groupID:     "non-existing-group-id",
			expectError: true,
		},
		{
			name:        "delete with empty group ID",
			groupID:     "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.DeleteGroup(context.Background(), accountID, tt.groupID)
			if tt.expectError {
				require.Error(t, err)
				sErr, ok := status.FromError(err)
				require.True(t, ok)
				require.Equal(t, sErr.Type(), status.NotFound)
			} else {
				require.NoError(t, err)

				group, err := store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, tt.groupID)
				require.Error(t, err)
				require.Nil(t, group)
			}
		})
	}
}

func TestSqlStore_DeleteGroups(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	tests := []struct {
		name        string
		groupIDs    []string
		expectError bool
	}{
		{
			name:        "delete multiple existing groups",
			groupIDs:    []string{"cfefqs706sqkneg59g4g", "cfefqs706sqkneg59g3g"},
			expectError: false,
		},
		{
			name:        "delete non-existing groups",
			groupIDs:    []string{"non-existing-id-1", "non-existing-id-2"},
			expectError: false,
		},
		{
			name:        "delete with empty group IDs list",
			groupIDs:    []string{},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.DeleteGroups(context.Background(), accountID, tt.groupIDs)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)

				for _, groupID := range tt.groupIDs {
					group, err := store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, groupID)
					require.Error(t, err)
					require.Nil(t, group)
				}
			}
		})
	}
}

func TestSqlStore_AddAndRemoveResourceFromGroup(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/store.sql", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanup)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"
	resourceId := "ctc4nci7qv9061u6ilfg"
	groupID := "cs1tnh0hhcjnqoiuebeg"

	res := &types.Resource{
		ID:   resourceId,
		Type: "host",
	}
	err = store.AddResourceToGroup(context.Background(), accountID, groupID, res)
	require.NoError(t, err)

	group, err := store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, groupID)
	require.NoError(t, err)
	require.Contains(t, group.Resources, *res)

	groups, err := store.GetResourceGroups(context.Background(), LockingStrengthNone, accountID, resourceId)
	require.NoError(t, err)
	require.Len(t, groups, 1)

	err = store.RemoveResourceFromGroup(context.Background(), accountID, groupID, res.ID)
	require.NoError(t, err)

	group, err = store.GetGroupByID(context.Background(), LockingStrengthNone, accountID, groupID)
	require.NoError(t, err)
	require.NotContains(t, group.Resources, *res)
}

func TestSqlStore_SaveGroups_LargeBatch(t *testing.T) {
	store, cleanup, err := NewTestStoreFromSQL(context.Background(), "../testdata/extended-store.sql", t.TempDir())
	t.Cleanup(cleanup)
	require.NoError(t, err)

	accountID := "bf1c8084-ba50-4ce7-9439-34653001fc3b"

	accountGroups, err := store.GetAccountGroups(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.Len(t, accountGroups, 3)

	groupsToSave := make([]*types.Group, 0)

	for i := 1; i <= 8000; i++ {
		groupsToSave = append(groupsToSave, &types.Group{
			ID:        fmt.Sprintf("%d", i),
			AccountID: accountID,
			Name:      fmt.Sprintf("group-%d", i),
		})
	}

	err = store.CreateGroups(context.Background(), accountID, groupsToSave)
	require.NoError(t, err)

	accountGroups, err = store.GetAccountGroups(context.Background(), LockingStrengthNone, accountID)
	require.NoError(t, err)
	require.Equal(t, 8003, len(accountGroups))
}
