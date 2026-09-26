//go:build !js && !plan9 && !ios && !android

package profilemanager

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
