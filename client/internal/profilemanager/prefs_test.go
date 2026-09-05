package profilemanager

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testPrefsSection struct {
	Mode uint8  `json:"mode"`
	Dest string `json:"dest"`
}

func TestProfilePrefs_RoundTrip(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		created, err := sm.AddProfile("work", username, nil)
		require.NoError(t, err)

		prefs, err := sm.ProfilePrefs(created.ID, username)
		require.NoError(t, err)

		require.NoError(t, prefs.Put("filedrop", testPrefsSection{Mode: 2, Dest: "/tmp/x"}))
		require.NoError(t, prefs.Put("other", map[string]int{"n": 1}))

		var got testPrefsSection
		found, err := prefs.Get("filedrop", &got)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, testPrefsSection{Mode: 2, Dest: "/tmp/x"}, got)

		var other map[string]int
		found, err = prefs.Get("other", &other)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, map[string]int{"n": 1}, other)
	})
}

func TestProfilePrefs_GetMissingNamespace(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		created, err := sm.AddProfile("work", username, nil)
		require.NoError(t, err)

		prefs, err := sm.ProfilePrefs(created.ID, username)
		require.NoError(t, err)

		var got testPrefsSection
		found, err := prefs.Get("filedrop", &got)
		require.NoError(t, err)
		assert.False(t, found)
	})
}

func TestProfilePrefs_RemoveNamespace(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		created, err := sm.AddProfile("work", username, nil)
		require.NoError(t, err)

		prefs, err := sm.ProfilePrefs(created.ID, username)
		require.NoError(t, err)

		require.NoError(t, prefs.Put("filedrop", testPrefsSection{Mode: 1}))
		require.NoError(t, prefs.Put("other", map[string]int{"n": 1}))
		require.NoError(t, prefs.Remove("filedrop"))
		require.NoError(t, prefs.Remove("missing"))

		var got testPrefsSection
		found, err := prefs.Get("filedrop", &got)
		require.NoError(t, err)
		assert.False(t, found)

		var other map[string]int
		found, err = prefs.Get("other", &other)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, map[string]int{"n": 1}, other)
	})
}

func TestProfilePrefs_RejectsInvalidID(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		_, err := sm.ProfilePrefs("../escape", username)
		assert.Error(t, err)
	})
}

func TestProfilePrefs_RejectsEmptyNamespace(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		created, err := sm.AddProfile("work", username, nil)
		require.NoError(t, err)

		prefs, err := sm.ProfilePrefs(created.ID, username)
		require.NoError(t, err)

		_, err = prefs.Get("", &testPrefsSection{})
		assert.Error(t, err)
		assert.Error(t, prefs.Put("", testPrefsSection{}))
		assert.Error(t, prefs.Remove(""))
	})
}

func TestProfilePrefs_DefaultProfile(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		prefs, err := sm.ProfilePrefs(defaultProfileName, username)
		require.NoError(t, err)

		require.NoError(t, prefs.Put("filedrop", testPrefsSection{Mode: 1}))

		expected := filepath.Join(filepath.Dir(DefaultConfigPath), "default"+prefsFileSuffix)
		_, err = os.Stat(expected)
		require.NoError(t, err)
	})
}

func TestRemoveProfile_DeletesPrefsFile(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		created, err := sm.AddProfile("work", username, nil)
		require.NoError(t, err)

		prefs, err := sm.ProfilePrefs(created.ID, username)
		require.NoError(t, err)
		require.NoError(t, prefs.Put("filedrop", testPrefsSection{Mode: 2}))

		configDir, err := sm.getConfigDir(username)
		require.NoError(t, err)
		prefsPath := filepath.Join(configDir, created.ID.String()+prefsFileSuffix)
		_, err = os.Stat(prefsPath)
		require.NoError(t, err)

		require.NoError(t, sm.RemoveProfile(created.ID, username))
		_, err = os.Stat(prefsPath)
		assert.True(t, errors.Is(err, os.ErrNotExist), "prefs file should be removed")
	})
}
