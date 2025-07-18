package profilemanager

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
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
	origDefaultConfigPath := DefaultConfigPath
	origActiveProfileStatePath := ActiveProfileStatePath
	origOldDefaultConfigPath := oldDefaultConfigPath
	origConfigDirOverride := ConfigDirOverride
	DefaultConfigPathDir = configDir
	DefaultConfigPath = filepath.Join(configDir, "default.json")
	ActiveProfileStatePath = filepath.Join(configDir, "active_profile.json")
	oldDefaultConfigPath = filepath.Join(configDir, "old_config.json")
	ConfigDirOverride = configDir
	// Clean up any files in the config dir to ensure isolation
	os.RemoveAll(configDir)
	os.MkdirAll(configDir, 0755) //nolint: errcheck
	defer func() {
		DefaultConfigPathDir = origDefaultConfigPathDir
		DefaultConfigPath = origDefaultConfigPath
		ActiveProfileStatePath = origActiveProfileStatePath
		oldDefaultConfigPath = origOldDefaultConfigPath
		ConfigDirOverride = origConfigDirOverride
	}()
	testFunc()
}

func TestServiceManager_CreateAndGetDefaultProfile(t *testing.T) {
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			sm := &ServiceManager{}
			err := sm.CreateDefaultProfile()
			assert.NoError(t, err)

			state, err := sm.GetActiveProfileState()
			assert.NoError(t, err)
			assert.Equal(t, state.Name, defaultProfileName) // No active profile state yet

			err = sm.SetActiveProfileStateToDefault()
			assert.NoError(t, err)

			active, err := sm.GetActiveProfileState()
			assert.NoError(t, err)
			assert.Equal(t, "default", active.Name)
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
			_, err = os.Stat(DefaultConfigPath)
			assert.NoError(t, err)
		})
	})
}

func TestServiceManager_SetActiveProfileState(t *testing.T) {
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			currUser, err := user.Current()
			assert.NoError(t, err)
			sm := &ServiceManager{}
			state := &ActiveProfileState{Name: "foo", Username: currUser.Username}
			err = sm.SetActiveProfileState(state)
			assert.NoError(t, err)

			// Should error on nil or incomplete state
			err = sm.SetActiveProfileState(nil)
			assert.Error(t, err)
			err = sm.SetActiveProfileState(&ActiveProfileState{Name: "", Username: ""})
			assert.Error(t, err)
		})
	})
}

func TestServiceManager_DefaultProfilePath(t *testing.T) {
	withTempConfigDir(t, func(configDir string) {
		withPatchedGlobals(t, configDir, func() {
			sm := &ServiceManager{}
			assert.Equal(t, DefaultConfigPath, sm.DefaultProfilePath())
		})
	})
}
