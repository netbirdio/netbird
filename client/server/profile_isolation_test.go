package server

import (
	"context"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/proto"
)

func TestSetConfig_ProfileIsolation(t *testing.T) {
	tempDir := t.TempDir()
	origDefaultProfileDir := profilemanager.DefaultConfigPathDir
	origDefaultConfigPath := profilemanager.DefaultConfigPath
	origActiveProfileStatePath := profilemanager.ActiveProfileStatePath
	profilemanager.ConfigDirOverride = tempDir
	profilemanager.DefaultConfigPathDir = tempDir
	profilemanager.ActiveProfileStatePath = tempDir + "/active_profile.json"
	profilemanager.DefaultConfigPath = filepath.Join(tempDir, "default.json")
	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDefaultProfileDir
		profilemanager.ActiveProfileStatePath = origActiveProfileStatePath
		profilemanager.DefaultConfigPath = origDefaultConfigPath
		profilemanager.ConfigDirOverride = ""
	})

	currUser, err := user.Current()
	require.NoError(t, err)

	// Create two profiles
	profileA := "profile-a"
	profileB := "profile-b"

	// Create config for Profile A
	icA := profilemanager.ConfigInput{
		ConfigPath:    filepath.Join(tempDir, profileA+".json"),
		ManagementURL: "https://management-a.netbird.io:443",
	}
	_, err = profilemanager.UpdateOrCreateConfig(icA)
	require.NoError(t, err)

	// Create config for Profile B
	icB := profilemanager.ConfigInput{
		ConfigPath:    filepath.Join(tempDir, profileB+".json"),
		ManagementURL: "https://management-b.netbird.io:443",
	}
	_, err = profilemanager.UpdateOrCreateConfig(icB)
	require.NoError(t, err)

	// Initialize Server
	ctx := context.Background()
	// New(ctx context.Context, logPath string, configPath string, profilesDisabled bool, updateSettingsDisabled bool)
	s := New(ctx, "console", "", false, false)

	// Set active profile to A (just to be in a valid likely state, though SetConfig is independent of active profile for target)
	pm := profilemanager.ServiceManager{}
	err = pm.SetActiveProfileState(&profilemanager.ActiveProfileState{
		Name:     profileA,
		Username: currUser.Username,
	})
	require.NoError(t, err)

	// 1. Update Profile A's Management URL via SetConfig
	newUrlA := "https://new-management-a.netbird.io:443"
	reqA := &proto.SetConfigRequest{
		ProfileName:   profileA,
		Username:      currUser.Username,
		ManagementUrl: newUrlA,
	}
	_, err = s.SetConfig(ctx, reqA)
	require.NoError(t, err)

	// Verify Profile A updated
	cfgA, err := profilemanager.GetConfig(filepath.Join(tempDir, profileA+".json"))
	require.NoError(t, err)
	require.Equal(t, newUrlA, cfgA.ManagementURL.String())

	// Verify Profile B UNCHANGED
	cfgB, err := profilemanager.GetConfig(filepath.Join(tempDir, profileB+".json"))
	require.NoError(t, err)
	require.Equal(t, "https://management-b.netbird.io:443", cfgB.ManagementURL.String())

	// 2. Update Profile B's Management URL via SetConfig
	newUrlB := "https://new-management-b.netbird.io:443"
	reqB := &proto.SetConfigRequest{
		ProfileName:   profileB,
		Username:      currUser.Username,
		ManagementUrl: newUrlB,
	}
	_, err = s.SetConfig(ctx, reqB)
	require.NoError(t, err)

	// Verify Profile B updated
	cfgB, err = profilemanager.GetConfig(filepath.Join(tempDir, profileB+".json"))
	require.NoError(t, err)
	require.Equal(t, newUrlB, cfgB.ManagementURL.String())

	// Verify Profile A UNCHANGED
	cfgA, err = profilemanager.GetConfig(filepath.Join(tempDir, profileA+".json"))
	require.NoError(t, err)
	require.Equal(t, newUrlA, cfgA.ManagementURL.String())
}
