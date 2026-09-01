package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	nbdex "github.com/netbirdio/netbird/idp/dex"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/controller"
	"github.com/netbirdio/netbird/management/internals/controllers/network_map/update_channel"
	"github.com/netbirdio/netbird/management/internals/modules/peers"
	ephemeral_manager "github.com/netbirdio/netbird/management/internals/modules/peers/ephemeral/manager"
	"github.com/netbirdio/netbird/management/internals/server/config"
	"github.com/netbirdio/netbird/management/server/activity"
	"github.com/netbirdio/netbird/management/server/cache"
	"github.com/netbirdio/netbird/management/server/idp"
	"github.com/netbirdio/netbird/management/server/integrations/port_forwarding"
	"github.com/netbirdio/netbird/management/server/job"
	"github.com/netbirdio/netbird/management/server/permissions"
	"github.com/netbirdio/netbird/management/server/settings"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/telemetry"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/auth"
	"github.com/netbirdio/netbird/shared/management/status"
)

func createManagerWithEmbeddedIdP(t testing.TB) (*DefaultAccountManager, *update_channel.PeersUpdateManager, error) {
	t.Helper()
	return createManagerWithEmbeddedIdPMode(t, "netbird.selfhosted")
}

func createManagerWithEmbeddedIdPMode(t testing.TB, singleAccountModeDomain string) (*DefaultAccountManager, *update_channel.PeersUpdateManager, error) {
	t.Helper()
	return createManagerWithEmbeddedIdPModeAndSetup(t, singleAccountModeDomain, nil)
}

func createManagerWithEmbeddedIdPModeAndSetup(
	t testing.TB,
	singleAccountModeDomain string,
	setupStore func(context.Context, store.Store) error,
) (*DefaultAccountManager, *update_channel.PeersUpdateManager, error) {
	t.Helper()

	ctx := context.Background()

	dataDir := t.TempDir()
	testStore, cleanUp, err := store.NewTestStoreFromSQL(ctx, "", dataDir)
	if err != nil {
		return nil, nil, err
	}
	t.Cleanup(cleanUp)
	if setupStore != nil {
		if err := setupStore(ctx, testStore); err != nil {
			return nil, nil, err
		}
	}

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
	peersManager := peers.NewManager(testStore, permissionsManager)

	cacheStore, err := cache.NewStore(ctx, 100*time.Millisecond, 300*time.Millisecond, 100)
	if err != nil {
		return nil, nil, err
	}

	updateManager := update_channel.NewPeersUpdateManager(metrics)
	requestBuffer := NewAccountRequestBuffer(ctx, testStore)
	networkMapController := controller.NewController(ctx, testStore, metrics, updateManager, requestBuffer, MockIntegratedValidator{}, settingsMockManager, "netbird.cloud", port_forwarding.NewControllerMock(), ephemeral_manager.NewEphemeralManager(testStore, peersManager), &config.Config{}, nil)
	manager, err := BuildManager(ctx, &config.Config{}, testStore, networkMapController, job.NewJobManager(nil, testStore, peersManager), idpManager, singleAccountModeDomain, eventStore, nil, false, MockIntegratedValidator{}, metrics, port_forwarding.NewControllerMock(), settingsMockManager, permissionsManager, false, cacheStore)
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

func TestDefaultAccountManager_IdentityProviderManagementBlocksUntilSingleAccountRemains(t *testing.T) {
	ctx := context.Background()
	manager, _, err := createManagerWithEmbeddedIdP(t)
	require.NoError(t, err)
	const (
		firstUserID  = "user-1"
		secondUserID = "user-2"
		connectorID  = "existing-connector"
	)
	firstAccount, err := manager.GetOrCreateAccountByUser(ctx, auth.UserAuth{UserId: firstUserID})
	require.NoError(t, err)
	secondAccount, err := manager.GetOrCreateAccountByUser(ctx, auth.UserAuth{UserId: secondUserID})
	require.NoError(t, err)
	require.NotEqual(t, firstAccount.Id, secondAccount.Id)

	embeddedManager, ok := manager.idpManager.(*idp.EmbeddedIdPManager)
	require.True(t, ok)
	_, err = embeddedManager.CreateConnector(ctx, &nbdex.ConnectorConfig{
		ID:       connectorID,
		Name:     "Existing OIDC connector",
		Type:     "oidc",
		Issuer:   "https://example.com",
		ClientID: "clientID",
	})
	require.NoError(t, err)

	var discoveryServer *httptest.Server
	discoveryServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(oidcProviderJSON{Issuer: discoveryServer.URL}); err != nil {
			t.Errorf("encode discovery response: %v", err)
		}
	}))
	t.Cleanup(discoveryServer.Close)

	identityProvider := func() *types.IdentityProvider {
		return &types.IdentityProvider{
			Name:     "Candidate OIDC connector",
			Type:     types.IdentityProviderTypeOIDC,
			Issuer:   discoveryServer.URL,
			ClientID: "clientID",
		}
	}

	tests := []struct {
		name string
		call func() error
	}{
		{
			name: "list",
			call: func() error {
				_, err := manager.GetIdentityProviders(ctx, secondAccount.Id, secondUserID)
				return err
			},
		},
		{
			name: "get",
			call: func() error {
				_, err := manager.GetIdentityProvider(ctx, secondAccount.Id, connectorID, secondUserID)
				return err
			},
		},
		{
			name: "create",
			call: func() error {
				_, err := manager.CreateIdentityProvider(ctx, secondAccount.Id, secondUserID, identityProvider())
				return err
			},
		},
		{
			name: "update",
			call: func() error {
				_, err := manager.UpdateIdentityProvider(ctx, secondAccount.Id, connectorID, secondUserID, identityProvider())
				return err
			},
		},
		{
			name: "delete",
			call: func() error {
				return manager.DeleteIdentityProvider(ctx, secondAccount.Id, connectorID, secondUserID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()
			require.Error(t, err)

			statusErr, ok := status.FromError(err)
			require.True(t, ok, "Identity provider operation should return a status error")
			assert.Equal(t, status.PreconditionFailed, statusErr.Type(), "Operation should fail closed outside single account mode")
		})
	}

	connector, err := embeddedManager.GetConnector(ctx, connectorID)
	require.NoError(t, err, "Denied operations must leave the existing connector unchanged")
	assert.Equal(t, "https://example.com", connector.Issuer, "Denied update must not replace the connector issuer")
	assert.Equal(t, "clientID", connector.ClientID, "Denied update must not replace the connector client ID")

	require.NoError(t, manager.Store.DeleteAccount(ctx, firstAccount))
	providers, err := manager.GetIdentityProviders(ctx, secondAccount.Id, secondUserID)
	require.NoError(t, err, "Connector access should be restored when one account remains")
	require.Len(t, providers, 1, "Existing connector should remain available")
	assert.Equal(t, connectorID, providers[0].ID, "Existing connector should be returned")
	assert.Equal(t, secondAccount.Id, providers[0].AccountID, "Connector should be scoped to the remaining account")
}

func TestDefaultAccountManager_BlocksIdPManagementWithMultipleAccounts(t *testing.T) {
	ctx := context.Background()
	var firstAccount, secondAccount *types.Account
	manager, _, err := createManagerWithEmbeddedIdPModeAndSetup(t, "netbird.selfhosted", func(ctx context.Context, testStore store.Store) error {
		firstAccount = newAccountWithId(ctx, "account-1", "user-1", "", "", "", false)
		if err := testStore.SaveAccount(ctx, firstAccount); err != nil {
			return err
		}

		secondAccount = newAccountWithId(ctx, "account-2", "user-2", "", "", "", false)
		return testStore.SaveAccount(ctx, secondAccount)
	})
	require.NoError(t, err)
	require.False(t, manager.singleAccountMode, "Migrated multi-account deployment should not enter single-account mode")

	_, err = manager.GetIdentityProviders(ctx, secondAccount.Id, "user-2")
	require.Error(t, err)
	statusErr, ok := status.FromError(err)
	require.True(t, ok, "Identity provider operation should return a status error")
	assert.Equal(t, status.PreconditionFailed, statusErr.Type(), "Migrated multi-account deployment must be denied")

	require.NoError(t, manager.Store.DeleteAccount(ctx, firstAccount))
	_, err = manager.GetIdentityProviders(ctx, secondAccount.Id, "user-2")
	require.Error(t, err)
}

func TestDefaultAccountManager_IdPManagementRequiresSingleAccountMode(t *testing.T) {
	manager, _, err := createManagerWithEmbeddedIdPMode(t, "")
	require.NoError(t, err)

	const userID = "testingUser"
	account, err := manager.GetOrCreateAccountByUser(context.Background(), auth.UserAuth{UserId: userID})
	require.NoError(t, err)

	_, err = manager.GetIdentityProviders(context.Background(), account.Id, userID)
	require.Error(t, err)

	statusErr, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, status.PreconditionFailed, statusErr.Type())
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

func TestValidateOIDCIssuer(t *testing.T) {
	tests := []struct {
		name           string
		setupServer    func() *httptest.Server
		expectedErr    error
		expectedErrMsg string
	}{
		{
			name: "issuer mismatch",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					resp := oidcProviderJSON{Issuer: "https://different-issuer.com"}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(resp)
				}))
			},
			expectedErr:    types.ErrIdentityProviderIssuerMismatch,
			expectedErrMsg: "does not match",
		},
		{
			name: "server returns non-200 status",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte("not found"))
				}))
			},
			expectedErr:    types.ErrIdentityProviderIssuerUnreachable,
			expectedErrMsg: "404",
		},
		{
			name: "server returns invalid JSON",
			setupServer: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte("invalid json"))
				}))
			},
			expectedErr:    types.ErrIdentityProviderIssuerUnreachable,
			expectedErrMsg: "failed to decode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.setupServer()
			defer server.Close()

			err := validateOIDCIssuer(context.Background(), server.URL)

			require.Error(t, err)
			assert.True(t, errors.Is(err, tt.expectedErr), "expected error %v, got %v", tt.expectedErr, err)
			if tt.expectedErrMsg != "" {
				assert.Contains(t, err.Error(), tt.expectedErrMsg)
			}
		})
	}
}

func TestValidateOIDCIssuer_Success(t *testing.T) {
	// Create a server that returns its own URL as the issuer
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		resp := oidcProviderJSON{Issuer: server.URL}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	err := validateOIDCIssuer(context.Background(), server.URL)
	require.NoError(t, err)
}

func TestValidateOIDCIssuer_UnreachableServer(t *testing.T) {
	// Use a URL that will definitely fail to connect
	err := validateOIDCIssuer(context.Background(), "http://localhost:59999")
	require.Error(t, err)
	assert.True(t, errors.Is(err, types.ErrIdentityProviderIssuerUnreachable))
}

func TestValidateOIDCIssuer_TrailingSlash(t *testing.T) {
	// Test that trailing slashes are handled correctly
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		// Return issuer without trailing slash
		resp := oidcProviderJSON{Issuer: server.URL}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Pass issuer with trailing slash
	err := validateOIDCIssuer(context.Background(), server.URL+"/")
	// This should fail because the issuer returned doesn't have trailing slash
	require.Error(t, err)
	assert.True(t, errors.Is(err, types.ErrIdentityProviderIssuerMismatch))
}
