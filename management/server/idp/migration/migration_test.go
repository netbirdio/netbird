package migration

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/types"
)

const testConnectorID = "oidc"

// mockMainStore implements MainStoreUpdater for testing.
type mockMainStore struct {
	users       []*types.User
	listErr     error
	updateErr   error
	updateCalls []updateCall
}

type updateCall struct {
	AccountID string
	OldID     string
	NewID     string
}

func (m *mockMainStore) ListUsers(_ context.Context) ([]*types.User, error) {
	return m.users, m.listErr
}

func (m *mockMainStore) UpdateUserID(_ context.Context, accountID, oldUserID, newUserID string) error {
	m.updateCalls = append(m.updateCalls, updateCall{accountID, oldUserID, newUserID})
	return m.updateErr
}

// mockActivityStore implements ActivityStoreUpdater for testing.
type mockActivityStore struct {
	updateErr   error
	updateCalls []activityUpdateCall
}

type activityUpdateCall struct {
	OldID string
	NewID string
}

func (m *mockActivityStore) UpdateUserID(_ context.Context, oldUserID, newUserID string) error {
	m.updateCalls = append(m.updateCalls, activityUpdateCall{oldUserID, newUserID})
	return m.updateErr
}

func TestMigrate_NormalMigration(t *testing.T) {
	mainStore := &mockMainStore{
		users: []*types.User{
			{Id: "user-1", AccountID: "acc-1"},
			{Id: "user-2", AccountID: "acc-1"},
		},
	}
	actStore := &mockActivityStore{}

	res, err := Migrate(context.Background(), &Config{
		ConnectorID:   testConnectorID,
		MainStore:     mainStore,
		ActivityStore: actStore,
	})

	require.NoError(t, err)
	assert.Equal(t, 2, res.Migrated)
	assert.Equal(t, 0, res.Skipped)
	assert.Len(t, mainStore.updateCalls, 2)
	assert.Len(t, actStore.updateCalls, 2)

	// Verify the new IDs are DEX-encoded
	for _, call := range mainStore.updateCalls {
		userID, connID, decErr := dex.DecodeDexUserID(call.NewID)
		require.NoError(t, decErr)
		assert.Equal(t, testConnectorID, connID)
		assert.Equal(t, call.OldID, userID)
	}
}

func TestMigrate_SkipAlreadyMigrated(t *testing.T) {
	alreadyMigrated := dex.EncodeDexUserID("original-user", testConnectorID)
	mainStore := &mockMainStore{
		users: []*types.User{
			{Id: alreadyMigrated, AccountID: "acc-1"},
			{Id: "not-migrated", AccountID: "acc-1"},
		},
	}
	actStore := &mockActivityStore{}

	res, err := Migrate(context.Background(), &Config{
		ConnectorID:   testConnectorID,
		MainStore:     mainStore,
		ActivityStore: actStore,
	})

	require.NoError(t, err)
	assert.Equal(t, 1, res.Migrated)
	assert.Equal(t, 1, res.Skipped)
	assert.Len(t, mainStore.updateCalls, 1)
	assert.Equal(t, "not-migrated", mainStore.updateCalls[0].OldID)
}

func TestMigrate_DryRun(t *testing.T) {
	mainStore := &mockMainStore{
		users: []*types.User{
			{Id: "user-1", AccountID: "acc-1"},
		},
	}
	actStore := &mockActivityStore{}

	res, err := Migrate(context.Background(), &Config{
		ConnectorID:   testConnectorID,
		DryRun:        true,
		MainStore:     mainStore,
		ActivityStore: actStore,
	})

	require.NoError(t, err)
	assert.Equal(t, 1, res.Migrated)
	// No actual updates should have been made
	assert.Empty(t, mainStore.updateCalls)
	assert.Empty(t, actStore.updateCalls)
}

func TestMigrate_EmptyUserList(t *testing.T) {
	mainStore := &mockMainStore{users: []*types.User{}}
	actStore := &mockActivityStore{}

	res, err := Migrate(context.Background(), &Config{
		ConnectorID:   testConnectorID,
		MainStore:     mainStore,
		ActivityStore: actStore,
	})

	require.NoError(t, err)
	assert.Equal(t, 0, res.Migrated)
	assert.Equal(t, 0, res.Skipped)
}

func TestMigrate_EmptyUserID(t *testing.T) {
	mainStore := &mockMainStore{
		users: []*types.User{
			{Id: "", AccountID: "acc-1"},
			{Id: "user-1", AccountID: "acc-1"},
		},
	}
	actStore := &mockActivityStore{}

	res, err := Migrate(context.Background(), &Config{
		ConnectorID:   testConnectorID,
		MainStore:     mainStore,
		ActivityStore: actStore,
	})

	require.NoError(t, err)
	assert.Equal(t, 1, res.Migrated)
	assert.Equal(t, 1, res.Skipped)
}

func TestMigrate_NilActivityStore(t *testing.T) {
	mainStore := &mockMainStore{
		users: []*types.User{
			{Id: "user-1", AccountID: "acc-1"},
		},
	}

	res, err := Migrate(context.Background(), &Config{
		ConnectorID: testConnectorID,
		MainStore:   mainStore,
		// ActivityStore is nil
	})

	require.NoError(t, err)
	assert.Equal(t, 1, res.Migrated)
	assert.Len(t, mainStore.updateCalls, 1)
}

func TestMigrate_EmptyConnectorID(t *testing.T) {
	mainStore := &mockMainStore{}

	_, err := Migrate(context.Background(), &Config{
		ConnectorID: "",
		MainStore:   mainStore,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "connector ID must not be empty")
}

func TestMigrate_ListUsersError(t *testing.T) {
	mainStore := &mockMainStore{listErr: errors.New("db error")}

	_, err := Migrate(context.Background(), &Config{
		ConnectorID: testConnectorID,
		MainStore:   mainStore,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "list users")
}

func TestMigrate_UpdateError(t *testing.T) {
	mainStore := &mockMainStore{
		users:     []*types.User{{Id: "user-1", AccountID: "acc-1"}},
		updateErr: errors.New("tx error"),
	}

	_, err := Migrate(context.Background(), &Config{
		ConnectorID: testConnectorID,
		MainStore:   mainStore,
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "update user ID")
}

func TestMigrate_Reconciliation(t *testing.T) {
	// Simulate a previously migrated user whose activity store wasn't updated
	alreadyMigrated := dex.EncodeDexUserID("original-user", testConnectorID)
	mainStore := &mockMainStore{
		users: []*types.User{
			{Id: alreadyMigrated, AccountID: "acc-1"},
		},
	}
	actStore := &mockActivityStore{}

	res, err := Migrate(context.Background(), &Config{
		ConnectorID:   testConnectorID,
		MainStore:     mainStore,
		ActivityStore: actStore,
	})

	require.NoError(t, err)
	assert.Equal(t, 0, res.Migrated)
	assert.Equal(t, 1, res.Skipped)
	// Reconciliation should have called activity store with the original -> new mapping
	require.Len(t, actStore.updateCalls, 1)
	assert.Equal(t, "original-user", actStore.updateCalls[0].OldID)
	assert.Equal(t, alreadyMigrated, actStore.updateCalls[0].NewID)
}

func TestMigrate_Idempotent(t *testing.T) {
	mainStore := &mockMainStore{
		users: []*types.User{
			{Id: "user-1", AccountID: "acc-1"},
			{Id: "user-2", AccountID: "acc-1"},
		},
	}
	actStore := &mockActivityStore{}

	// First run
	res1, err := Migrate(context.Background(), &Config{
		ConnectorID:   testConnectorID,
		MainStore:     mainStore,
		ActivityStore: actStore,
	})
	require.NoError(t, err)
	assert.Equal(t, 2, res1.Migrated)

	// Simulate that the store now has the migrated IDs
	for _, call := range mainStore.updateCalls {
		for i, u := range mainStore.users {
			if u.Id == call.OldID {
				mainStore.users[i].Id = call.NewID
			}
		}
	}
	mainStore.updateCalls = nil
	actStore.updateCalls = nil

	// Second run should skip all
	res2, err := Migrate(context.Background(), &Config{
		ConnectorID:   testConnectorID,
		MainStore:     mainStore,
		ActivityStore: actStore,
	})
	require.NoError(t, err)
	assert.Equal(t, 0, res2.Migrated)
	assert.Equal(t, 2, res2.Skipped)
	assert.Empty(t, mainStore.updateCalls)
}
