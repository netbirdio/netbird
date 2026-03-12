package migration

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/types"
)

// testStore is a hand-written mock for MigrationStore.
type testStore struct {
	listUsersFunc    func(ctx context.Context) ([]*types.User, error)
	updateUserIDFunc func(ctx context.Context, accountID, oldUserID, newUserID string) error
	updateCalls      []updateUserIDCall
}

type updateUserIDCall struct {
	AccountID string
	OldUserID string
	NewUserID string
}

func (s *testStore) ListUsers(ctx context.Context) ([]*types.User, error) {
	return s.listUsersFunc(ctx)
}

func (s *testStore) UpdateUserID(ctx context.Context, accountID, oldUserID, newUserID string) error {
	s.updateCalls = append(s.updateCalls, updateUserIDCall{accountID, oldUserID, newUserID})
	return s.updateUserIDFunc(ctx, accountID, oldUserID, newUserID)
}

type testServer struct {
	store      MigrationStore
	eventStore MigrationEventStore
}

func (s *testServer) Store() MigrationStore        { return s.store }
func (s *testServer) EventStore() MigrationEventStore { return s.eventStore }

func TestSeedConnectorFromEnv(t *testing.T) {
	t.Run("returns nil when env var is not set", func(t *testing.T) {
		os.Unsetenv(idpSeedInfoKey)

		conn, err := SeedConnectorFromEnv()
		assert.NoError(t, err)
		assert.Nil(t, conn)
	})

	t.Run("returns nil when env var is empty", func(t *testing.T) {
		t.Setenv(idpSeedInfoKey, "")

		conn, err := SeedConnectorFromEnv()
		assert.NoError(t, err)
		assert.Nil(t, conn)
	})

	t.Run("returns error on invalid base64", func(t *testing.T) {
		t.Setenv(idpSeedInfoKey, "not-valid-base64!!!")

		conn, err := SeedConnectorFromEnv()
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "base64 decode")
	})

	t.Run("returns error on invalid JSON", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("not json"))
		t.Setenv(idpSeedInfoKey, encoded)

		conn, err := SeedConnectorFromEnv()
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "json unmarshal")
	})

	t.Run("successfully decodes valid connector", func(t *testing.T) {
		expected := dex.Connector{
			Type: "oidc",
			Name: "Test Provider",
			ID:   "test-provider",
			Config: map[string]any{
				"issuer":       "https://example.com",
				"clientID":     "my-client-id",
				"clientSecret": "my-secret",
			},
		}

		data, err := json.Marshal(expected)
		require.NoError(t, err)

		encoded := base64.StdEncoding.EncodeToString(data)
		t.Setenv(idpSeedInfoKey, encoded)

		conn, err := SeedConnectorFromEnv()
		assert.NoError(t, err)
		require.NotNil(t, conn)
		assert.Equal(t, expected.Type, conn.Type)
		assert.Equal(t, expected.Name, conn.Name)
		assert.Equal(t, expected.ID, conn.ID)
		assert.Equal(t, expected.Config["issuer"], conn.Config["issuer"])
	})
}

func TestIsSeedInfoPresent(t *testing.T) {
	t.Run("returns false when env var is not set", func(t *testing.T) {
		os.Unsetenv(idpSeedInfoKey)

		assert.False(t, IsSeedInfoPresent())
	})

	t.Run("returns false when env var is empty", func(t *testing.T) {
		t.Setenv(idpSeedInfoKey, "")

		assert.False(t, IsSeedInfoPresent())
	})

	t.Run("returns true when env var is set to a value", func(t *testing.T) {
		t.Setenv(idpSeedInfoKey, "some-value")

		assert.True(t, IsSeedInfoPresent())
	})
}

func TestMigrateUsersToStaticConnectors(t *testing.T) {
	connector := &dex.Connector{
		Type: "oidc",
		Name: "Test Provider",
		ID:   "test-connector",
	}

	t.Run("succeeds with no users", func(t *testing.T) {
		ms := &testStore{
			listUsersFunc:    func(ctx context.Context) ([]*types.User, error) { return nil, nil },
			updateUserIDFunc: func(ctx context.Context, accountID, oldUserID, newUserID string) error { return nil },
		}

		srv := &testServer{store: ms}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.NoError(t, err)
	})

	t.Run("returns error when ListUsers fails", func(t *testing.T) {
		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return nil, fmt.Errorf("db error")
			},
			updateUserIDFunc: func(ctx context.Context, accountID, oldUserID, newUserID string) error { return nil },
		}

		srv := &testServer{store: ms}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to list users")
	})

	t.Run("migrates single user with correct encoded ID", func(t *testing.T) {
		user := &types.User{Id: "user-1", AccountID: "account-1"}
		expectedNewID := dex.EncodeDexUserID("user-1", "test-connector")

		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return []*types.User{user}, nil
			},
			updateUserIDFunc: func(ctx context.Context, accountID, oldUserID, newUserID string) error {
				return nil
			},
		}

		srv := &testServer{store: ms}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.NoError(t, err)
		require.Len(t, ms.updateCalls, 1)
		assert.Equal(t, "account-1", ms.updateCalls[0].AccountID)
		assert.Equal(t, "user-1", ms.updateCalls[0].OldUserID)
		assert.Equal(t, expectedNewID, ms.updateCalls[0].NewUserID)
	})

	t.Run("migrates multiple users", func(t *testing.T) {
		users := []*types.User{
			{Id: "user-1", AccountID: "account-1"},
			{Id: "user-2", AccountID: "account-1"},
			{Id: "user-3", AccountID: "account-2"},
		}

		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return users, nil
			},
			updateUserIDFunc: func(ctx context.Context, accountID, oldUserID, newUserID string) error {
				return nil
			},
		}

		srv := &testServer{store: ms}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.NoError(t, err)
		assert.Len(t, ms.updateCalls, 3)
	})

	t.Run("returns error when UpdateUserID fails", func(t *testing.T) {
		users := []*types.User{
			{Id: "user-1", AccountID: "account-1"},
			{Id: "user-2", AccountID: "account-1"},
		}

		callCount := 0
		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return users, nil
			},
			updateUserIDFunc: func(ctx context.Context, accountID, oldUserID, newUserID string) error {
				callCount++
				if callCount == 2 {
					return fmt.Errorf("update failed")
				}
				return nil
			},
		}

		srv := &testServer{store: ms}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to update user ID for user user-2")
	})

	t.Run("stops on first UpdateUserID error", func(t *testing.T) {
		users := []*types.User{
			{Id: "user-1", AccountID: "account-1"},
			{Id: "user-2", AccountID: "account-1"},
		}

		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return users, nil
			},
			updateUserIDFunc: func(ctx context.Context, accountID, oldUserID, newUserID string) error {
				return fmt.Errorf("update failed")
			},
		}

		srv := &testServer{store: ms}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.Error(t, err)
		assert.Len(t, ms.updateCalls, 1) // stopped after first error
	})

	t.Run("skips already migrated users", func(t *testing.T) {
		alreadyMigratedID := dex.EncodeDexUserID("user-1", "test-connector")
		users := []*types.User{
			{Id: alreadyMigratedID, AccountID: "account-1"},
		}

		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return users, nil
			},
			updateUserIDFunc: func(ctx context.Context, accountID, oldUserID, newUserID string) error {
				return nil
			},
		}

		srv := &testServer{store: ms}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.NoError(t, err)
		assert.Len(t, ms.updateCalls, 0)
	})

	t.Run("migrates only non-migrated users in mixed state", func(t *testing.T) {
		alreadyMigratedID := dex.EncodeDexUserID("user-1", "test-connector")
		users := []*types.User{
			{Id: alreadyMigratedID, AccountID: "account-1"},
			{Id: "user-2", AccountID: "account-1"},
			{Id: "user-3", AccountID: "account-2"},
		}

		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return users, nil
			},
			updateUserIDFunc: func(ctx context.Context, accountID, oldUserID, newUserID string) error {
				return nil
			},
		}

		srv := &testServer{store: ms}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.NoError(t, err)
		// Only user-2 and user-3 should be migrated
		assert.Len(t, ms.updateCalls, 2)
		assert.Equal(t, "user-2", ms.updateCalls[0].OldUserID)
		assert.Equal(t, "user-3", ms.updateCalls[1].OldUserID)
	})

	t.Run("dry run does not call UpdateUserID", func(t *testing.T) {
		t.Setenv(dryRunEnvKey, "true")

		users := []*types.User{
			{Id: "user-1", AccountID: "account-1"},
			{Id: "user-2", AccountID: "account-1"},
		}

		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return users, nil
			},
			updateUserIDFunc: func(ctx context.Context, accountID, oldUserID, newUserID string) error {
				t.Fatal("UpdateUserID should not be called in dry-run mode")
				return nil
			},
		}

		srv := &testServer{store: ms}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.NoError(t, err)
		assert.Len(t, ms.updateCalls, 0)
	})

	t.Run("dry run skips already migrated users", func(t *testing.T) {
		t.Setenv(dryRunEnvKey, "true")

		alreadyMigratedID := dex.EncodeDexUserID("user-1", "test-connector")
		users := []*types.User{
			{Id: alreadyMigratedID, AccountID: "account-1"},
			{Id: "user-2", AccountID: "account-1"},
		}

		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return users, nil
			},
			updateUserIDFunc: func(ctx context.Context, accountID, oldUserID, newUserID string) error {
				t.Fatal("UpdateUserID should not be called in dry-run mode")
				return nil
			},
		}

		srv := &testServer{store: ms}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.NoError(t, err)
	})

	t.Run("dry run disabled by default", func(t *testing.T) {
		user := &types.User{Id: "user-1", AccountID: "account-1"}

		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return []*types.User{user}, nil
			},
			updateUserIDFunc: func(ctx context.Context, accountID, oldUserID, newUserID string) error {
				return nil
			},
		}

		srv := &testServer{store: ms}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.NoError(t, err)
		assert.Len(t, ms.updateCalls, 1) // proves it's not in dry-run
	})
}
