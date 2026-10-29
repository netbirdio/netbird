package mobile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/profilemanager"
	"github.com/netbirdio/netbird/client/mdm"
)

type fakeFetcher struct{ values map[string]any }

func (f *fakeFetcher) Fetch() map[string]any { return f.values }

func newTestProfileManager(t *testing.T) *ProfileManager {
	t.Helper()
	origDir := profilemanager.DefaultConfigPathDir
	origPath := profilemanager.DefaultConfigPath
	origActive := profilemanager.ActiveProfileStatePath
	t.Cleanup(func() {
		profilemanager.DefaultConfigPathDir = origDir
		profilemanager.DefaultConfigPath = origPath
		profilemanager.ActiveProfileStatePath = origActive
	})

	configDir := t.TempDir()
	pm := NewProfileManager(configDir, "mobile")
	_, err := profilemanager.UpdateOrCreateConfig(profilemanager.ConfigInput{
		ConfigPath: filepath.Join(configDir, defaultConfigFilename),
	})
	require.NoError(t, err)
	return pm
}

func privateKeyOf(t *testing.T, pm *ProfileManager, id string) string {
	t.Helper()
	path, err := pm.getProfileConfigPath(id)
	require.NoError(t, err)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var cfg struct{ PrivateKey string }
	require.NoError(t, json.Unmarshal(raw, &cfg))
	return cfg.PrivateKey
}

func TestLogoutProfile_DisableProfiles(t *testing.T) {
	pm := newTestProfileManager(t)
	other, err := pm.AddProfile("work")
	require.NoError(t, err)
	require.NoError(t, pm.SwitchProfile(profilemanager.DefaultProfileName))
	require.NotEmpty(t, privateKeyOf(t, pm, profilemanager.DefaultProfileName))
	require.NotEmpty(t, privateKeyOf(t, pm, other.ID))

	pm.SetMDMLoader(mdm.NewLoader(&fakeFetcher{values: map[string]any{
		mdm.KeyDisableProfiles: true,
	}}))

	err = pm.LogoutProfile(other.ID)
	assert.ErrorIs(t, err, ErrProfilesDisabled)
	assert.NotEmpty(t, privateKeyOf(t, pm, other.ID))

	require.NoError(t, pm.LogoutProfile(profilemanager.DefaultProfileName))
	assert.Empty(t, privateKeyOf(t, pm, profilemanager.DefaultProfileName))
}

func TestLogoutProfile_ProfilesAllowed(t *testing.T) {
	pm := newTestProfileManager(t)
	other, err := pm.AddProfile("work")
	require.NoError(t, err)
	require.NoError(t, pm.SwitchProfile(profilemanager.DefaultProfileName))

	pm.SetMDMLoader(mdm.NewLoader(&fakeFetcher{values: map[string]any{
		mdm.KeyDisableProfiles: false,
	}}))

	require.NoError(t, pm.LogoutProfile(other.ID))
	assert.Empty(t, privateKeyOf(t, pm, other.ID))
}
