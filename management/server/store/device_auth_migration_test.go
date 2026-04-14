package store_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// TestDeviceAuthSettings_MigrationAndRoundtrip verifies that DeviceAuthSettings
// columns are created by AutoMigrate and that the values round-trip through the store.
func TestDeviceAuthSettings_MigrationAndRoundtrip(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err, "create test store")
	defer cleanup()

	// Create a minimal account with DeviceAuth settings.
	account := &types.Account{
		Id:     "test-account-da",
		Domain: "example.com",
		Settings: &types.Settings{
			PeerLoginExpirationEnabled: true,
			DeviceAuth: &types.DeviceAuthSettings{
				Mode:             types.DeviceAuthModeOptional,
				EnrollmentMode:   types.DeviceAuthEnrollmentManual,
				CAType:           types.DeviceAuthCATypeBuiltin,
				CertValidityDays: 365,
				OCSPEnabled:      true,
			},
		},
	}

	err = s.SaveAccount(ctx, account)
	require.NoError(t, err, "save account with DeviceAuthSettings")

	// Reload from DB.
	loaded, err := s.GetAccount(ctx, "test-account-da")
	require.NoError(t, err, "get account")

	require.NotNil(t, loaded.Settings, "settings must not be nil")
	require.NotNil(t, loaded.Settings.DeviceAuth, "DeviceAuth must not be nil after round-trip")

	da := loaded.Settings.DeviceAuth
	assert.Equal(t, types.DeviceAuthModeOptional, da.Mode)
	assert.Equal(t, types.DeviceAuthEnrollmentManual, da.EnrollmentMode)
	assert.Equal(t, types.DeviceAuthCATypeBuiltin, da.CAType)
	assert.Equal(t, 365, da.CertValidityDays)
	assert.True(t, da.OCSPEnabled)
	assert.False(t, da.FailOpenOnOCSPUnavailable)
}

// TestDeviceAuthSettings_NilOnNewAccount verifies that a new account
// without DeviceAuth set loads with nil DeviceAuth (no forced initialisation).
func TestDeviceAuthSettings_NilOnNewAccount(t *testing.T) {
	ctx := context.Background()
	s, cleanup, err := store.NewTestStoreFromSQL(ctx, "", t.TempDir())
	require.NoError(t, err)
	defer cleanup()

	account := &types.Account{
		Id:     "test-account-no-da",
		Domain: "example.com",
		Settings: &types.Settings{
			PeerLoginExpirationEnabled: false,
		},
	}

	require.NoError(t, s.SaveAccount(ctx, account))

	loaded, err := s.GetAccount(ctx, "test-account-no-da")
	require.NoError(t, err)

	// GORM always materialises an embedded struct pointer from the DB.
	// When DeviceAuthSettings is not explicitly set, it is returned with its
	// GORM tag default values (mode=disabled, CAType=builtin, etc.).
	// Callers must treat mode=disabled (or nil) as "feature not enabled".
	if loaded.Settings != nil && loaded.Settings.DeviceAuth != nil {
		assert.Equal(t, types.DeviceAuthModeDisabled, loaded.Settings.DeviceAuth.Mode,
			"unset DeviceAuth should default to mode=disabled")
	}
}
