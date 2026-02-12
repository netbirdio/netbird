package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetupSetConfigReq_FlagGuard(t *testing.T) {
	// Save original vars
	origMgmtURL := managementURL
	origAdminURL := adminURL
	defer func() {
		managementURL = origMgmtURL
		adminURL = origAdminURL
	}()

	managementURL = "https://cli-mgmt.netbird.io"
	adminURL = "https://cli-admin.netbird.io"

	// Case 1: Flags NOT changed
	// Reset flags changed status
	rootCmd.PersistentFlags().Lookup("management-url").Changed = false
	rootCmd.PersistentFlags().Lookup("admin-url").Changed = false

	req := setupSetConfigReq(nil, upCmd, "profile-A", "user-A")

	// Should NOT have management/admin URL set
	require.Equal(t, "", req.ManagementUrl)
	require.Equal(t, "", req.AdminURL)

	// Case 2: Management URL flag changed
	rootCmd.PersistentFlags().Lookup("management-url").Changed = true

	req = setupSetConfigReq(nil, rootCmd, "profile-A", "user-A")

	require.Equal(t, managementURL, req.ManagementUrl)
	// Admin URL still unchanged
	require.Equal(t, "", req.AdminURL)

	// Case 3: Both changed
	rootCmd.PersistentFlags().Lookup("admin-url").Changed = true

	req = setupSetConfigReq(nil, upCmd, "profile-A", "user-A")

	require.Equal(t, managementURL, req.ManagementUrl)
	require.Equal(t, adminURL, req.AdminURL)
}

func TestSetupLoginRequest_FlagGuard(t *testing.T) {
	// Save original vars
	origMgmtURL := managementURL
	defer func() {
		managementURL = origMgmtURL
	}()

	managementURL = "https://cli-mgmt.netbird.io"

	// Case 1: Flag NOT changed
	rootCmd.PersistentFlags().Lookup("management-url").Changed = false

	req, err := setupLoginRequest("setup-key", nil, upCmd)
	require.NoError(t, err)

	require.Equal(t, "", req.ManagementUrl)

	// Case 2: Flag changed
	rootCmd.PersistentFlags().Lookup("management-url").Changed = true

	req, err = setupLoginRequest("setup-key", nil, upCmd)
	require.NoError(t, err)

	require.Equal(t, managementURL, req.ManagementUrl)
}
