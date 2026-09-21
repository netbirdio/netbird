package profilemanager

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testPrefsSection struct {
	Mode uint8  `json:"mode"`
	Dest string `json:"dest"`
}

func TestProfilePrefs_RoundTrip(t *testing.T) {
	withTestSM(t, func(sm *ServiceManager, username string) {
		created, err := sm.AddProfile("work", username)
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
		created, err := sm.AddProfile("work", username)
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
		created, err := sm.AddProfile("work", username)
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
		created, err := sm.AddProfile("work", username)
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
		created, err := sm.AddProfile("work", username)
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

const (
	prefsLockChildEnv = "NB_PREFS_LOCK_CHILD"
	prefsLockPathEnv  = "NB_PREFS_LOCK_PATH"
)

// TestPrefsFileLock_ExcludesAnotherProcess pins the guarantee the in-process
// mutex cannot give: on the mobile clients the app and the network extension
// are separate processes writing the same preference file, each replacing its
// own section. A write reads every section, replaces one and writes them all
// back, so two processes overlapping there lose one of the two updates — a
// trusted SSH host key or a saved session list silently reverting.
//
// The lock is tested directly rather than through concurrent Put calls: the
// underlying write is atomic (temp file plus rename) and both sides would keep
// writing, so a lost update is restored by the next iteration and a racing
// test passes with or without the lock.
//
// The child is this same test binary re-executed, since only a real second
// process exercises a file lock at all.
func TestPrefsFileLock_ExcludesAnotherProcess(t *testing.T) {
	if path := os.Getenv(prefsLockPathEnv); os.Getenv(prefsLockChildEnv) != "" && path != "" {
		require.NoError(t, os.WriteFile(path+".child-started", []byte("1"), 0o600))

		unlock, err := lockPrefsFile(path)
		require.NoError(t, err)
		defer unlock()

		require.NoError(t, os.WriteFile(path+".child-acquired",
			[]byte(time.Now().Format(time.RFC3339Nano)), 0o600))
		return
	}

	path := filepath.Join(t.TempDir(), "locked.prefs.json")

	unlock, err := lockPrefsFile(path)
	require.NoError(t, err)

	// Released explicitly below to timestamp it, and again on the way out so
	// an assertion that fires earlier cannot leave the child blocked on a lock
	// nobody will drop.
	held := true
	release := func() time.Time {
		if !held {
			return time.Time{}
		}
		held = false
		at := time.Now()
		unlock()
		return at
	}
	defer release()

	child := exec.Command(os.Args[0], "-test.run=TestPrefsFileLock_ExcludesAnotherProcess")
	child.Env = append(os.Environ(), prefsLockChildEnv+"=1", prefsLockPathEnv+"="+path)
	require.NoError(t, child.Start())
	t.Cleanup(func() { _ = child.Process.Kill() })

	require.Eventually(t, func() bool {
		_, err := os.Stat(path + ".child-started")
		return err == nil
	}, 30*time.Second, 10*time.Millisecond, "the child never reached the lock")

	// The child has announced itself and should now be blocking on the lock.
	// Watch for the whole grace period rather than sampling once at the end:
	// a single check cannot tell a lock that blocks from a child that was
	// simply descheduled, and would pass against a broken lock.
	grace := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(grace) {
		_, err := os.Stat(path + ".child-acquired")
		require.True(t, os.IsNotExist(err),
			"the child took the lock while this process was still holding it")
		time.Sleep(10 * time.Millisecond)
	}

	released := release()
	require.NoError(t, child.Wait())

	raw, err := os.ReadFile(path + ".child-acquired")
	require.NoError(t, err, "the child never took the lock after it was released")
	acquired, err := time.Parse(time.RFC3339Nano, string(raw))
	require.NoError(t, err)
	assert.False(t, acquired.Before(released),
		"the child reports taking the lock before this process released it")
}
