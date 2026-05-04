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
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/types"
)

// testStore is a hand-written mock for MigrationStore.
type testStore struct {
	listUsersFunc      func(ctx context.Context) ([]*types.User, error)
	updateUserIDFunc   func(ctx context.Context, accountID, oldUserID, newUserID string) error
	updateUserInfoFunc func(ctx context.Context, userID, email, name string) error
	checkSchemaFunc    func(checks []SchemaCheck) []SchemaError
	updateCalls        []updateUserIDCall
	updateInfoCalls    []updateUserInfoCall
}

type updateUserIDCall struct {
	AccountID string
	OldUserID string
	NewUserID string
}

type updateUserInfoCall struct {
	UserID string
	Email  string
	Name   string
}

func (s *testStore) ListUsers(ctx context.Context) ([]*types.User, error) {
	return s.listUsersFunc(ctx)
}

func (s *testStore) UpdateUserID(ctx context.Context, accountID, oldUserID, newUserID string) error {
	s.updateCalls = append(s.updateCalls, updateUserIDCall{accountID, oldUserID, newUserID})
	return s.updateUserIDFunc(ctx, accountID, oldUserID, newUserID)
}

func (s *testStore) UpdateUserInfo(ctx context.Context, userID, email, name string) error {
	s.updateInfoCalls = append(s.updateInfoCalls, updateUserInfoCall{userID, email, name})
	if s.updateUserInfoFunc != nil {
		return s.updateUserInfoFunc(ctx, userID, email, name)
	}
	return nil
}

func (s *testStore) CheckSchema(checks []SchemaCheck) []SchemaError {
	if s.checkSchemaFunc != nil {
		return s.checkSchemaFunc(checks)
	}
	return nil
}

type testServer struct {
	store      Store
	eventStore EventStore
}

func (s *testServer) Store() Store           { return s.store }
func (s *testServer) EventStore() EventStore { return s.eventStore }

func TestSeedConnectorFromEnv(t *testing.T) {
	t.Run("returns ErrNoSeedInfo when env var is not set", func(t *testing.T) {
		os.Unsetenv(idpSeedInfoKey)

		conn, err := SeedConnectorFromEnv()
		assert.ErrorIs(t, err, ErrNoSeedInfo)
		assert.Nil(t, conn)
	})

	t.Run("returns ErrNoSeedInfo when env var is empty", func(t *testing.T) {
		t.Setenv(idpSeedInfoKey, "")

		conn, err := SeedConnectorFromEnv()
		assert.ErrorIs(t, err, ErrNoSeedInfo)
		assert.Nil(t, conn)
	})

	t.Run("returns error on invalid base64", func(t *testing.T) {
		t.Setenv(idpSeedInfoKey, "not-valid-base64!!!")

		conn, err := SeedConnectorFromEnv()
		assert.NotErrorIs(t, err, ErrNoSeedInfo)
		assert.Error(t, err)
		assert.Nil(t, conn)
		assert.Contains(t, err.Error(), "base64 decode")
	})

	t.Run("returns error on invalid JSON", func(t *testing.T) {
		encoded := base64.StdEncoding.EncodeToString([]byte("not json"))
		t.Setenv(idpSeedInfoKey, encoded)

		conn, err := SeedConnectorFromEnv()
		assert.NotErrorIs(t, err, ErrNoSeedInfo)
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

func TestPopulateUserInfo(t *testing.T) {
	noopUpdateID := func(ctx context.Context, accountID, oldUserID, newUserID string) error { return nil }

	t.Run("succeeds with no users", func(t *testing.T) {
		ms := &testStore{
			listUsersFunc:    func(ctx context.Context) ([]*types.User, error) { return nil, nil },
			updateUserIDFunc: noopUpdateID,
		}
		mockIDP := &idp.MockIDP{
			GetAllAccountsFunc: func(ctx context.Context) (map[string][]*idp.UserData, error) {
				return map[string][]*idp.UserData{}, nil
			},
		}

		srv := &testServer{store: ms}
		err := PopulateUserInfo(srv, mockIDP, false)
		assert.NoError(t, err)
		assert.Empty(t, ms.updateInfoCalls)
	})

	t.Run("returns error when ListUsers fails", func(t *testing.T) {
		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return nil, fmt.Errorf("db error")
			},
			updateUserIDFunc: noopUpdateID,
		}
		mockIDP := &idp.MockIDP{}

		srv := &testServer{store: ms}
		err := PopulateUserInfo(srv, mockIDP, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to list users")
	})

	t.Run("returns error when GetAllAccounts fails", func(t *testing.T) {
		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return []*types.User{{Id: "user-1", AccountID: "acc-1"}}, nil
			},
			updateUserIDFunc: noopUpdateID,
		}
		mockIDP := &idp.MockIDP{
			GetAllAccountsFunc: func(ctx context.Context) (map[string][]*idp.UserData, error) {
				return nil, fmt.Errorf("idp error")
			},
		}

		srv := &testServer{store: ms}
		err := PopulateUserInfo(srv, mockIDP, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to fetch accounts from IDP")
	})

	t.Run("updates user with missing email and name", func(t *testing.T) {
		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return []*types.User{
					{Id: "user-1", AccountID: "acc-1", Email: "", Name: ""},
				}, nil
			},
			updateUserIDFunc: noopUpdateID,
		}
		mockIDP := &idp.MockIDP{
			GetAllAccountsFunc: func(ctx context.Context) (map[string][]*idp.UserData, error) {
				return map[string][]*idp.UserData{
					"acc-1": {
						{ID: "user-1", Email: "user1@example.com", Name: "User One"},
					},
				}, nil
			},
		}

		srv := &testServer{store: ms}
		err := PopulateUserInfo(srv, mockIDP, false)
		assert.NoError(t, err)
		require.Len(t, ms.updateInfoCalls, 1)
		assert.Equal(t, "user-1", ms.updateInfoCalls[0].UserID)
		assert.Equal(t, "user1@example.com", ms.updateInfoCalls[0].Email)
		assert.Equal(t, "User One", ms.updateInfoCalls[0].Name)
	})

	t.Run("updates only missing email when name exists", func(t *testing.T) {
		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return []*types.User{
					{Id: "user-1", AccountID: "acc-1", Email: "", Name: "Existing Name"},
				}, nil
			},
			updateUserIDFunc: noopUpdateID,
		}
		mockIDP := &idp.MockIDP{
			GetAllAccountsFunc: func(ctx context.Context) (map[string][]*idp.UserData, error) {
				return map[string][]*idp.UserData{
					"acc-1": {{ID: "user-1", Email: "user1@example.com", Name: "IDP Name"}},
				}, nil
			},
		}

		srv := &testServer{store: ms}
		err := PopulateUserInfo(srv, mockIDP, false)
		assert.NoError(t, err)
		require.Len(t, ms.updateInfoCalls, 1)
		assert.Equal(t, "user1@example.com", ms.updateInfoCalls[0].Email)
		assert.Equal(t, "Existing Name", ms.updateInfoCalls[0].Name)
	})

	t.Run("updates only missing name when email exists", func(t *testing.T) {
		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return []*types.User{
					{Id: "user-1", AccountID: "acc-1", Email: "existing@example.com", Name: ""},
				}, nil
			},
			updateUserIDFunc: noopUpdateID,
		}
		mockIDP := &idp.MockIDP{
			GetAllAccountsFunc: func(ctx context.Context) (map[string][]*idp.UserData, error) {
				return map[string][]*idp.UserData{
					"acc-1": {{ID: "user-1", Email: "idp@example.com", Name: "IDP Name"}},
				}, nil
			},
		}

		srv := &testServer{store: ms}
		err := PopulateUserInfo(srv, mockIDP, false)
		assert.NoError(t, err)
		require.Len(t, ms.updateInfoCalls, 1)
		assert.Equal(t, "existing@example.com", ms.updateInfoCalls[0].Email)
		assert.Equal(t, "IDP Name", ms.updateInfoCalls[0].Name)
	})

	t.Run("skips users that already have both email and name", func(t *testing.T) {
		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return []*types.User{
					{Id: "user-1", AccountID: "acc-1", Email: "user1@example.com", Name: "User One"},
				}, nil
			},
			updateUserIDFunc: noopUpdateID,
		}
		mockIDP := &idp.MockIDP{
			GetAllAccountsFunc: func(ctx context.Context) (map[string][]*idp.UserData, error) {
				return map[string][]*idp.UserData{
					"acc-1": {{ID: "user-1", Email: "different@example.com", Name: "Different Name"}},
				}, nil
			},
		}

		srv := &testServer{store: ms}
		err := PopulateUserInfo(srv, mockIDP, false)
		assert.NoError(t, err)
		assert.Empty(t, ms.updateInfoCalls)
	})

	t.Run("skips service users", func(t *testing.T) {
		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return []*types.User{
					{Id: "svc-1", AccountID: "acc-1", Email: "", Name: "", IsServiceUser: true},
				}, nil
			},
			updateUserIDFunc: noopUpdateID,
		}
		mockIDP := &idp.MockIDP{
			GetAllAccountsFunc: func(ctx context.Context) (map[string][]*idp.UserData, error) {
				return map[string][]*idp.UserData{
					"acc-1": {{ID: "svc-1", Email: "svc@example.com", Name: "Service"}},
				}, nil
			},
		}

		srv := &testServer{store: ms}
		err := PopulateUserInfo(srv, mockIDP, false)
		assert.NoError(t, err)
		assert.Empty(t, ms.updateInfoCalls)
	})

	t.Run("skips users not found in IDP", func(t *testing.T) {
		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return []*types.User{
					{Id: "user-1", AccountID: "acc-1", Email: "", Name: ""},
				}, nil
			},
			updateUserIDFunc: noopUpdateID,
		}
		mockIDP := &idp.MockIDP{
			GetAllAccountsFunc: func(ctx context.Context) (map[string][]*idp.UserData, error) {
				return map[string][]*idp.UserData{
					"acc-1": {{ID: "different-user", Email: "other@example.com", Name: "Other"}},
				}, nil
			},
		}

		srv := &testServer{store: ms}
		err := PopulateUserInfo(srv, mockIDP, false)
		assert.NoError(t, err)
		assert.Empty(t, ms.updateInfoCalls)
	})

	t.Run("looks up dex-encoded user IDs by original ID", func(t *testing.T) {
		dexEncodedID := dex.EncodeDexUserID("original-idp-id", "my-connector")

		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return []*types.User{
					{Id: dexEncodedID, AccountID: "acc-1", Email: "", Name: ""},
				}, nil
			},
			updateUserIDFunc: noopUpdateID,
		}
		mockIDP := &idp.MockIDP{
			GetAllAccountsFunc: func(ctx context.Context) (map[string][]*idp.UserData, error) {
				return map[string][]*idp.UserData{
					"acc-1": {{ID: "original-idp-id", Email: "user@example.com", Name: "User"}},
				}, nil
			},
		}

		srv := &testServer{store: ms}
		err := PopulateUserInfo(srv, mockIDP, false)
		assert.NoError(t, err)
		require.Len(t, ms.updateInfoCalls, 1)
		assert.Equal(t, dexEncodedID, ms.updateInfoCalls[0].UserID)
		assert.Equal(t, "user@example.com", ms.updateInfoCalls[0].Email)
		assert.Equal(t, "User", ms.updateInfoCalls[0].Name)
	})

	t.Run("handles multiple users across multiple accounts", func(t *testing.T) {
		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return []*types.User{
					{Id: "user-1", AccountID: "acc-1", Email: "", Name: ""},
					{Id: "user-2", AccountID: "acc-1", Email: "already@set.com", Name: "Already Set"},
					{Id: "user-3", AccountID: "acc-2", Email: "", Name: ""},
				}, nil
			},
			updateUserIDFunc: noopUpdateID,
		}
		mockIDP := &idp.MockIDP{
			GetAllAccountsFunc: func(ctx context.Context) (map[string][]*idp.UserData, error) {
				return map[string][]*idp.UserData{
					"acc-1": {
						{ID: "user-1", Email: "u1@example.com", Name: "User 1"},
						{ID: "user-2", Email: "u2@example.com", Name: "User 2"},
					},
					"acc-2": {
						{ID: "user-3", Email: "u3@example.com", Name: "User 3"},
					},
				}, nil
			},
		}

		srv := &testServer{store: ms}
		err := PopulateUserInfo(srv, mockIDP, false)
		assert.NoError(t, err)
		require.Len(t, ms.updateInfoCalls, 2)
		assert.Equal(t, "user-1", ms.updateInfoCalls[0].UserID)
		assert.Equal(t, "u1@example.com", ms.updateInfoCalls[0].Email)
		assert.Equal(t, "user-3", ms.updateInfoCalls[1].UserID)
		assert.Equal(t, "u3@example.com", ms.updateInfoCalls[1].Email)
	})

	t.Run("returns error when UpdateUserInfo fails", func(t *testing.T) {
		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return []*types.User{
					{Id: "user-1", AccountID: "acc-1", Email: "", Name: ""},
				}, nil
			},
			updateUserIDFunc: noopUpdateID,
			updateUserInfoFunc: func(ctx context.Context, userID, email, name string) error {
				return fmt.Errorf("db write error")
			},
		}
		mockIDP := &idp.MockIDP{
			GetAllAccountsFunc: func(ctx context.Context) (map[string][]*idp.UserData, error) {
				return map[string][]*idp.UserData{
					"acc-1": {{ID: "user-1", Email: "u1@example.com", Name: "User 1"}},
				}, nil
			},
		}

		srv := &testServer{store: ms}
		err := PopulateUserInfo(srv, mockIDP, false)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to update user info for user-1")
	})

	t.Run("stops on first UpdateUserInfo error", func(t *testing.T) {
		callCount := 0
		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return []*types.User{
					{Id: "user-1", AccountID: "acc-1", Email: "", Name: ""},
					{Id: "user-2", AccountID: "acc-1", Email: "", Name: ""},
				}, nil
			},
			updateUserIDFunc: noopUpdateID,
			updateUserInfoFunc: func(ctx context.Context, userID, email, name string) error {
				callCount++
				return fmt.Errorf("db write error")
			},
		}
		mockIDP := &idp.MockIDP{
			GetAllAccountsFunc: func(ctx context.Context) (map[string][]*idp.UserData, error) {
				return map[string][]*idp.UserData{
					"acc-1": {
						{ID: "user-1", Email: "u1@example.com", Name: "U1"},
						{ID: "user-2", Email: "u2@example.com", Name: "U2"},
					},
				}, nil
			},
		}

		srv := &testServer{store: ms}
		err := PopulateUserInfo(srv, mockIDP, false)
		assert.Error(t, err)
		assert.Equal(t, 1, callCount)
	})

	t.Run("dry run does not call UpdateUserInfo", func(t *testing.T) {
		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return []*types.User{
					{Id: "user-1", AccountID: "acc-1", Email: "", Name: ""},
					{Id: "user-2", AccountID: "acc-1", Email: "", Name: ""},
				}, nil
			},
			updateUserIDFunc: noopUpdateID,
			updateUserInfoFunc: func(ctx context.Context, userID, email, name string) error {
				t.Fatal("UpdateUserInfo should not be called in dry-run mode")
				return nil
			},
		}
		mockIDP := &idp.MockIDP{
			GetAllAccountsFunc: func(ctx context.Context) (map[string][]*idp.UserData, error) {
				return map[string][]*idp.UserData{
					"acc-1": {
						{ID: "user-1", Email: "u1@example.com", Name: "U1"},
						{ID: "user-2", Email: "u2@example.com", Name: "U2"},
					},
				}, nil
			},
		}

		srv := &testServer{store: ms}
		err := PopulateUserInfo(srv, mockIDP, true)
		assert.NoError(t, err)
		assert.Empty(t, ms.updateInfoCalls)
	})

	t.Run("skips user when IDP has empty email and name too", func(t *testing.T) {
		ms := &testStore{
			listUsersFunc: func(ctx context.Context) ([]*types.User, error) {
				return []*types.User{
					{Id: "user-1", AccountID: "acc-1", Email: "", Name: ""},
				}, nil
			},
			updateUserIDFunc: noopUpdateID,
		}
		mockIDP := &idp.MockIDP{
			GetAllAccountsFunc: func(ctx context.Context) (map[string][]*idp.UserData, error) {
				return map[string][]*idp.UserData{
					"acc-1": {{ID: "user-1", Email: "", Name: ""}},
				}, nil
			},
		}

		srv := &testServer{store: ms}
		err := PopulateUserInfo(srv, mockIDP, false)
		assert.NoError(t, err)
		assert.Empty(t, ms.updateInfoCalls)
	})
}

func TestSchemaError_String(t *testing.T) {
	t.Run("missing table", func(t *testing.T) {
		e := SchemaError{Table: "jobs"}
		assert.Equal(t, `table "jobs" is missing`, e.String())
	})

	t.Run("missing column", func(t *testing.T) {
		e := SchemaError{Table: "users", Column: "email"}
		assert.Equal(t, `column "email" on table "users" is missing`, e.String())
	})
}

func TestRequiredSchema(t *testing.T) {
	// Verify RequiredSchema covers all the tables touched by UpdateUserID and UpdateUserInfo.
	expectedTables := []string{
		"users",
		"personal_access_tokens",
		"peers",
		"accounts",
		"user_invites",
		"proxy_access_tokens",
		"jobs",
	}

	schemaTableNames := make([]string, len(RequiredSchema))
	for i, s := range RequiredSchema {
		schemaTableNames[i] = s.Table
	}

	for _, expected := range expectedTables {
		assert.Contains(t, schemaTableNames, expected, "RequiredSchema should include table %q", expected)
	}
}

func TestCheckSchema_MockStore(t *testing.T) {
	t.Run("returns nil when all schema exists", func(t *testing.T) {
		ms := &testStore{
			checkSchemaFunc: func(checks []SchemaCheck) []SchemaError {
				return nil
			},
		}
		errs := ms.CheckSchema(RequiredSchema)
		assert.Empty(t, errs)
	})

	t.Run("returns errors for missing tables", func(t *testing.T) {
		ms := &testStore{
			checkSchemaFunc: func(checks []SchemaCheck) []SchemaError {
				return []SchemaError{
					{Table: "jobs"},
					{Table: "proxy_access_tokens"},
				}
			},
		}
		errs := ms.CheckSchema(RequiredSchema)
		require.Len(t, errs, 2)
		assert.Equal(t, "jobs", errs[0].Table)
		assert.Equal(t, "", errs[0].Column)
		assert.Equal(t, "proxy_access_tokens", errs[1].Table)
	})

	t.Run("returns errors for missing columns", func(t *testing.T) {
		ms := &testStore{
			checkSchemaFunc: func(checks []SchemaCheck) []SchemaError {
				return []SchemaError{
					{Table: "users", Column: "email"},
					{Table: "users", Column: "name"},
				}
			},
		}
		errs := ms.CheckSchema(RequiredSchema)
		require.Len(t, errs, 2)
		assert.Equal(t, "users", errs[0].Table)
		assert.Equal(t, "email", errs[0].Column)
	})
}
