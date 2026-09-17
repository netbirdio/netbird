package profilemanager

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/ipcauth"
)

type testPrefsSection struct {
	Mode uint8  `json:"mode"`
	Dest string `json:"dest"`
}

// currentUsername returns the account the prefs store keys its legacy config
// directory by. Profile ownership itself is carried by an ipcauth.Identity, but
// the on-disk layout is still per-username.
func currentUsername(t *testing.T) string {
	t.Helper()
	u, err := user.Current()
	require.NoError(t, err)
	return u.Username
}

func TestProfilePrefs_RoundTrip(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		username := currentUsername(t)
		created, err := sm.AddProfile("work", &userID)
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
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		username := currentUsername(t)
		created, err := sm.AddProfile("work", &userID)
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
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		username := currentUsername(t)
		created, err := sm.AddProfile("work", &userID)
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
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		username := currentUsername(t)
		_, err := sm.ProfilePrefs("../escape", username)
		assert.Error(t, err)
	})
}

func TestProfilePrefs_RejectsEmptyNamespace(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		username := currentUsername(t)
		created, err := sm.AddProfile("work", &userID)
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
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		username := currentUsername(t)
		prefs, err := sm.ProfilePrefs(defaultProfileName, username)
		require.NoError(t, err)

		require.NoError(t, prefs.Put("filedrop", testPrefsSection{Mode: 1}))

		expected := filepath.Join(filepath.Dir(DefaultConfigPath), "default"+prefsFileSuffix)
		_, err = os.Stat(expected)
		require.NoError(t, err)
	})
}

func TestRemoveProfile_DeletesPrefsFile(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, userID ipcauth.Identity) {
		username := currentUsername(t)
		created, err := sm.AddProfile("work", &userID)
		require.NoError(t, err)

		prefs, err := sm.ProfilePrefs(created.ID, username)
		require.NoError(t, err)
		require.NoError(t, prefs.Put("filedrop", testPrefsSection{Mode: 2}))

		configDir, err := sm.getConfigDirLegacy(username)
		require.NoError(t, err)
		prefsPath := filepath.Join(configDir, created.ID.String()+prefsFileSuffix)
		_, err = os.Stat(prefsPath)
		require.NoError(t, err)

		require.NoError(t, sm.RemoveProfile(created.ID, userID))
		_, err = os.Stat(prefsPath)
		assert.True(t, errors.Is(err, os.ErrNotExist), "prefs file should be removed")
	})
}
