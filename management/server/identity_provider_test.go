package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/types"
)

func TestDefaultAccountManager_CreateIdentityProvider_Validation(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)

	userID := "testingUser"
	account, err := manager.GetOrCreateAccountByUser(context.Background(), userID, "")
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
	account, err := manager.GetOrCreateAccountByUser(context.Background(), userID, "")
	require.NoError(t, err)

	// Should return empty list (stub implementation)
	providers, err := manager.GetIdentityProviders(context.Background(), account.Id, userID)
	require.NoError(t, err)
	assert.Empty(t, providers)
}

func TestDefaultAccountManager_GetIdentityProvider_NotFound(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)

	userID := "testingUser"
	account, err := manager.GetOrCreateAccountByUser(context.Background(), userID, "")
	require.NoError(t, err)

	// Should return not found error (stub implementation)
	_, err = manager.GetIdentityProvider(context.Background(), account.Id, "any-id", userID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestDefaultAccountManager_UpdateIdentityProvider_Validation(t *testing.T) {
	manager, _, err := createManager(t)
	require.NoError(t, err)

	userID := "testingUser"
	account, err := manager.GetOrCreateAccountByUser(context.Background(), userID, "")
	require.NoError(t, err)

	// Should fail validation before reaching "not implemented" error
	invalidIDP := &types.IdentityProvider{
		Name: "", // Empty name should fail validation
	}

	_, err = manager.UpdateIdentityProvider(context.Background(), account.Id, "some-id", userID, invalidIDP)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name is required")
}
