package migration

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

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

type mockServer struct {
	s          store.Store
	eventStore activity.Store
}

func (m *mockServer) Store() store.Store {
	return m.s
}

func (m *mockServer) EventStore() activity.Store {
	return m.eventStore
}

func TestMigrateUsersToStaticConnectors(t *testing.T) {
	connector := &dex.Connector{
		Type: "oidc",
		Name: "Test Provider",
		ID:   "test-connector",
	}

	t.Run("succeeds with no users", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().ListUsers(gomock.Any()).Return(nil, nil)

		srv := &mockServer{s: mockStore}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.NoError(t, err)
	})

	t.Run("returns error when ListUsers fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().ListUsers(gomock.Any()).Return(nil, fmt.Errorf("db error"))

		srv := &mockServer{s: mockStore}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to list users")
	})

	t.Run("migrates single user with correct encoded ID", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		user := &types.User{Id: "user-1", AccountID: "account-1"}
		expectedNewID := dex.EncodeDexUserID("user-1", "test-connector")

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().ListUsers(gomock.Any()).Return([]*types.User{user}, nil)
		mockStore.EXPECT().UpdateUserID(gomock.Any(), "account-1", "user-1", expectedNewID).Return(nil)

		srv := &mockServer{s: mockStore}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.NoError(t, err)
	})

	t.Run("migrates multiple users", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		users := []*types.User{
			{Id: "user-1", AccountID: "account-1"},
			{Id: "user-2", AccountID: "account-1"},
			{Id: "user-3", AccountID: "account-2"},
		}

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().ListUsers(gomock.Any()).Return(users, nil)
		for _, u := range users {
			expectedNewID := dex.EncodeDexUserID(u.Id, connector.ID)
			mockStore.EXPECT().UpdateUserID(gomock.Any(), u.AccountID, u.Id, expectedNewID).Return(nil)
		}

		srv := &mockServer{s: mockStore}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.NoError(t, err)
	})

	t.Run("returns error when UpdateUserID fails", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		users := []*types.User{
			{Id: "user-1", AccountID: "account-1"},
			{Id: "user-2", AccountID: "account-1"},
		}

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().ListUsers(gomock.Any()).Return(users, nil)
		mockStore.EXPECT().UpdateUserID(gomock.Any(), "account-1", "user-1", gomock.Any()).Return(nil)
		mockStore.EXPECT().UpdateUserID(gomock.Any(), "account-1", "user-2", gomock.Any()).Return(fmt.Errorf("update failed"))

		srv := &mockServer{s: mockStore}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to update user ID for user user-2")
	})

	t.Run("stops on first UpdateUserID error", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		users := []*types.User{
			{Id: "user-1", AccountID: "account-1"},
			{Id: "user-2", AccountID: "account-1"},
		}

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().ListUsers(gomock.Any()).Return(users, nil)
		mockStore.EXPECT().UpdateUserID(gomock.Any(), "account-1", "user-1", gomock.Any()).Return(fmt.Errorf("update failed"))

		srv := &mockServer{s: mockStore}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.Error(t, err)
	})

	t.Run("skips already migrated users", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		alreadyMigratedID := dex.EncodeDexUserID("user-1", "test-connector")
		users := []*types.User{
			{Id: alreadyMigratedID, AccountID: "account-1"},
		}

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().ListUsers(gomock.Any()).Return(users, nil)
		// UpdateUserID should NOT be called for already-migrated users

		srv := &mockServer{s: mockStore}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.NoError(t, err)
	})

	t.Run("migrates only non-migrated users in mixed state", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		alreadyMigratedID := dex.EncodeDexUserID("user-1", "test-connector")
		users := []*types.User{
			{Id: alreadyMigratedID, AccountID: "account-1"},
			{Id: "user-2", AccountID: "account-1"},
			{Id: "user-3", AccountID: "account-2"},
		}

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().ListUsers(gomock.Any()).Return(users, nil)
		// Only user-2 and user-3 should be migrated
		mockStore.EXPECT().UpdateUserID(gomock.Any(), "account-1", "user-2", dex.EncodeDexUserID("user-2", connector.ID)).Return(nil)
		mockStore.EXPECT().UpdateUserID(gomock.Any(), "account-2", "user-3", dex.EncodeDexUserID("user-3", connector.ID)).Return(nil)

		srv := &mockServer{s: mockStore}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.NoError(t, err)
	})

	t.Run("dry run does not call UpdateUserID", func(t *testing.T) {
		t.Setenv(dryRunEnvKey, "true")
		ctrl := gomock.NewController(t)

		users := []*types.User{
			{Id: "user-1", AccountID: "account-1"},
			{Id: "user-2", AccountID: "account-1"},
		}

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().ListUsers(gomock.Any()).Return(users, nil)
		// UpdateUserID should NOT be called in dry-run mode

		srv := &mockServer{s: mockStore}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.NoError(t, err)
	})

	t.Run("dry run skips already migrated users", func(t *testing.T) {
		t.Setenv(dryRunEnvKey, "true")
		ctrl := gomock.NewController(t)

		alreadyMigratedID := dex.EncodeDexUserID("user-1", "test-connector")
		users := []*types.User{
			{Id: alreadyMigratedID, AccountID: "account-1"},
			{Id: "user-2", AccountID: "account-1"},
		}

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().ListUsers(gomock.Any()).Return(users, nil)
		// No UpdateUserID calls expected

		srv := &mockServer{s: mockStore}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.NoError(t, err)
	})

	t.Run("dry run disabled by default", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		user := &types.User{Id: "user-1", AccountID: "account-1"}

		mockStore := store.NewMockStore(ctrl)
		mockStore.EXPECT().ListUsers(gomock.Any()).Return([]*types.User{user}, nil)
		mockStore.EXPECT().UpdateUserID(gomock.Any(), "account-1", "user-1", gomock.Any()).Return(nil)

		srv := &mockServer{s: mockStore}
		err := MigrateUsersToStaticConnectors(srv, connector)
		assert.NoError(t, err)
	})
}
