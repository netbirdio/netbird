package server

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	ephemeral_manager "github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral/manager"
	"github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
)

func createManagerWithEmbeddedIdP(t testing.TB) (*DefaultAccountManager, *update_channel.PeersUpdateManager, error) {
	t.Helper()

	ctx := context.Background()

	dataDir := t.TempDir()
	testStore, cleanUp, err := store.NewTestStoreFromSQL(ctx, "", dataDir)
	if err != nil {
		return nil, nil, err
	}
	t.Cleanup(cleanUp)

	// Create embedded IdP manager
	embeddedConfig := &idp.EmbeddedIdPConfig{
		Enabled: true,
		Issuer:  "http://localhost:5556/dex",
		Storage: idp.EmbeddedStorageConfig{
			Type: "sqlite3",
			Config: idp.EmbeddedStorageTypeConfig{
				File: filepath.Join(dataDir, "dex.db"),
			},
		},
	}

	idpManager, err := idp.NewEmbeddedIdPManager(ctx, embeddedConfig, nil)
	if err != nil {
		return nil, nil, err
	}
	t.Cleanup(func() { _ = idpManager.Stop(ctx) })

	eventStore := &activity.InMemoryEventStore{}

	metrics, err := telemetry.NewDefaultAppMetrics(ctx)
	if err != nil {
		return nil, nil, err
	}

	ctrl := gomock.NewController(t)
	t.Cleanup(ctrl.Finish)

	settingsMockManager := settings.NewMockManager(ctrl)
	settingsMockManager.EXPECT().
		GetExtraSettings(gomock.Any(), gomock.Any()).
		Return(&types.ExtraSettings{}, nil).
		AnyTimes()
	settingsMockManager.EXPECT().
		UpdateExtraSettings(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(false, nil).
		AnyTimes()

	permissionsManager := permissions.NewManager(testStore)

	updateManager := update_channel.NewPeersUpdateManager(metrics)
	requestBuffer := NewAccountRequestBuffer(ctx, testStore)
	networkMapController := controller.NewController(ctx, testStore, metrics, updateManager, requestBuffer, MockIntegratedValidator{}, settingsMockManager, "netbird.cloud", port_forwarding.NewControllerMock(), ephemeral_manager.NewEphemeralManager(testStore, peers.NewManager(testStore, permissionsManager)), &config.Config{})
	manager, err := BuildManager(ctx, &config.Config{}, testStore, networkMapController, idpManager, "", eventStore, nil, false, MockIntegratedValidator{}, metrics, port_forwarding.NewControllerMock(), settingsMockManager, permissionsManager, false)
	if err != nil {
		return nil, nil, err
	}

	return manager, updateManager, nil
}

func TestDefaultAccountManager_CreateIdentityProvider_Validation(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)

	userID := "testingUser"
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: userID})
	require.NoError(t, err)

	testCases := []struct {
		name        string
		idp         *types.IdentityProvider
		expectError bool
		errorMsg    string
	}{
		{
			name: "Missing Name",
			idp: &types.IdentityProvider{
				Type:     types.IdentityProviderTypeOIDC,
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
			},
			expectError: true,
			errorMsg:    "name is required",
		},
		{
			name: "Missing Type",
			idp: &types.IdentityProvider{
				Name:     "Test IDP",
				Issuer:   "https://issuer.example.com",
				ClientID: "client-id",
			},
			expectError: true,
			errorMsg:    "type is required",
		},
		{
			name: "Missing Issuer",
			idp: &types.IdentityProvider{
				Name:     "Test IDP",
				Type:     types.IdentityProviderTypeOIDC,
				ClientID: "client-id",
			},
			expectError: true,
			errorMsg:    "issuer is required",
		},
		{
			name: "Missing ClientID",
			idp: &types.IdentityProvider{
				Name:   "Test IDP",
				Type:   types.IdentityProviderTypeOIDC,
				Issuer: "https://issuer.example.com",
			},
			expectError: true,
			errorMsg:    "client ID is required",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := manager.CreateIdentityProvider(context.Background(), account.Id, userID, tc.idp)
			if tc.expectError {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			}
		})
	}
}

func TestDefaultAccountManager_GetIdentityProviders(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)

	userID := "testingUser"
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: userID})
	require.NoError(t, err)

	// Should return empty list (stub implementation)
	providers, err := manager.GetIdentityProviders(context.Background(), account.Id, userID)
	require.NoError(t, err)
	assert.Empty(t, providers)
}

func TestDefaultAccountManager_GetIdentityProvider_NotFound(t *testing.T) {
	manager, _, err := createManagerWithEmbeddedIdP(t)
	require.NoError(t, err)

	userID := "testingUser"
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: userID})
	require.NoError(t, err)

	// Should return not found error when identity provider doesn't exist
	_, err = manager.GetIdentityProvider(context.Background(), account.Id, "any-id", userID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestDefaultAccountManager_UpdateIdentityProvider_Validation(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)

	userID := "testingUser"
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: userID})
	require.NoError(t, err)

	// Should fail validation before reaching "not implemented" error
	invalidIDP := &types.IdentityProvider{
		Name: "", // Empty name should fail validation
	}

	_, err = manager.UpdateIdentityProvider(context.Background(), account.Id, "some-id", userID, invalidIDP)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}
