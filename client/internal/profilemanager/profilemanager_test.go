package profilemanager

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/util"
)

func withTempConfigDir(t *testing.T, testFunc func(configDir string)) {
	t.Helper()
	tempDir := t.TempDir()
	t.Setenv("NETBIRD_CONFIG_DIR", tempDir)
	defer os.Unsetenv("NETBIRD_CONFIG_DIR")
	testFunc(tempDir)
}

func withPatchedGlobals(t *testing.T, configDir string, testFunc func()) {
	origDefaultConfigPathDir := DefaultConfigPathDir
	origDefaultConfigPath := defaultConfigPath
	origActiveProfileStatePath := ActiveProfileStatePath
	origOldDefaultConfigPath := oldDefaultConfigPath
	origConfigDirOverride := ConfigDirOverride
	DefaultConfigPathDir = configDir
	defaultConfigPath = filepath.Join(configDir, "default.json")
	ActiveProfileStatePath = filepath.Join(configDir, "active_profile.json")
	oldDefaultConfigPath = filepath.Join(configDir, "old_config.json")
	ConfigDirOverride = configDir
	// Clean up any files in the config dir to ensure isolation
	os.RemoveAll(configDir)
	os.MkdirAll(configDir, 0755) //nolint: errcheck
	defer func() {
		DefaultConfigPathDir = origDefaultConfigPathDir
		defaultConfigPath = origDefaultConfigPath
		ActiveProfileStatePath = origActiveProfileStatePath
		oldDefaultConfigPath = origOldDefaultConfigPath
		ConfigDirOverride = origConfigDirOverride
	}()
	testFunc()
}

func TestProfileManager_AddListRemoveProfile(t *testing.T) {
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			pm := NewProfileManager()
			profile := Profile{Name: "testprofile"}

			err := pm.AddProfile(profile)
			assert.NoError(t, err)

			profiles, err := pm.ListProfiles()
			assert.NoError(t, err)
			var found bool
			for _, p := range profiles {
				if p.Name == "testprofile" {
					found = true
					break
				}
			}
			assert.True(t, found, "profile should be listed after adding")

			err = pm.RemoveProfile("testprofile")
			assert.NoError(t, err)

			profiles, err = pm.ListProfiles()
			assert.NoError(t, err)
			for _, p := range profiles {
				assert.NotEqual(t, "testprofile", p.Name, "profile should be removed")
			}
		})
	})
}

func TestProfileManager_SwitchProfile(t *testing.T) {
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			pm := NewProfileManager()
			profile := Profile{Name: "profile1"}
			err := pm.AddProfile(profile)
			assert.NoError(t, err)

			err = pm.SwitchProfile("profile1")
			assert.NoError(t, err)

			active, err := pm.GetActiveProfile()
			assert.NoError(t, err)
			assert.Equal(t, "profile1", active.Name)
		})
	})
}

func TestServiceManager_CreateAndGetDefaultProfile(t *testing.T) {
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			sm := &ServiceManager{}
			err := sm.CreateDefaultProfile()
			assert.NoError(t, err)

			_, err = sm.GetActiveProfileState()
			assert.Error(t, err) // No active profile state yet

			err = sm.SetActiveProfileStateToDefault()
			assert.NoError(t, err)

			active, err := sm.GetActiveProfileState()
			assert.NoError(t, err)
			assert.Equal(t, "default", active.Name)
			assert.Equal(t, defaultConfigPath, active.Path)
		})
	})
}

func TestServiceManager_CopyDefaultProfileIfNotExists(t *testing.T) {
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			sm := &ServiceManager{}

			// Case: old default config does not exist
			ok, err := sm.CopyDefaultProfileIfNotExists()
			assert.False(t, ok)
			assert.ErrorIs(t, err, ErrorOldDefaultConfigNotFound)

			// Case: old default config exists, should be moved
			f, err := os.Create(oldDefaultConfigPath)
			assert.NoError(t, err)
			f.Close()

			ok, err = sm.CopyDefaultProfileIfNotExists()
			assert.True(t, ok)
			assert.NoError(t, err)
			_, err = os.Stat(defaultConfigPath)
			assert.NoError(t, err)
		})
	})
}

func TestServiceManager_SetActiveProfileState(t *testing.T) {
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			sm := &ServiceManager{}
			state := &ActiveProfileState{Name: "foo", Path: "/tmp/foo.json"}
			err := sm.SetActiveProfileState(state)
			assert.NoError(t, err)

			// Should error on nil or incomplete state
			err = sm.SetActiveProfileState(nil)
			assert.Error(t, err)
			err = sm.SetActiveProfileState(&ActiveProfileState{Name: "", Path: ""})
			assert.Error(t, err)
		})
	})
}

func TestServiceManager_SetActiveProfileStateToDefault(t *testing.T) {
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			sm := &ServiceManager{}
			err := sm.SetActiveProfileStateToDefault()
			assert.NoError(t, err)

			var state ActiveProfileState
			_, err = util.ReadJson(ActiveProfileStatePath, &state)
			assert.NoError(t, err)
			assert.Equal(t, "default", state.Name)
			assert.Equal(t, defaultConfigPath, state.Path)
		})
	})
}

func TestServiceManager_DefaultProfilePath(t *testing.T) {
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			sm := &ServiceManager{}
			assert.Equal(t, defaultConfigPath, sm.DefaultProfilePath())
		})
	})
}
