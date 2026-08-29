//go:build (linux && !android) || freebsd

package server

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/configs"
)

// withRuntimeDir points configs.RuntimeDir at a temp tree for the test.
func withRuntimeDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	prev := configs.RuntimeDir
	configs.RuntimeDir = root
	t.Cleanup(func() { configs.RuntimeDir = prev })
	return root
}

func permOf(t *testing.T, dir string) os.FileMode {
	t.Helper()
	info, err := os.Stat(dir)
	require.NoError(t, err)
	return info.Mode().Perm()
}

// The runtime dir is shared: the daemon advertises its socket there and
// unprivileged clients list it to find one. Making the xauth dir traversable
// must not cost the read bit that listing needs.
func TestEnsureTraversableKeepsTheRuntimeDirReadable(t *testing.T) {
	root := withRuntimeDir(t)
	require.NoError(t, os.Chmod(root, 0o755))

	sub := filepath.Join(root, vncXAuthSubdir)
	require.NoError(t, os.Mkdir(sub, 0o700))

	require.NoError(t, ensureTraversable(sub))

	assert.Equal(t, os.FileMode(0o755), permOf(t, root), "an already-traversable shared dir must be left alone")
	assert.Equal(t, os.FileMode(0o711), permOf(t, sub), "the xauth dir gains traversal, keeping its own bits")
}

// A runtime dir that is not traversable gains execute, and nothing else: no
// read bit is handed out that was not there before.
func TestEnsureTraversableAddsOnlyExecute(t *testing.T) {
	root := withRuntimeDir(t)
	require.NoError(t, os.Chmod(root, 0o700))

	sub := filepath.Join(root, vncXAuthSubdir)
	require.NoError(t, os.Mkdir(sub, 0o700))

	require.NoError(t, ensureTraversable(sub))

	assert.Equal(t, os.FileMode(0o711), permOf(t, root))
	assert.Equal(t, os.FileMode(0o711), permOf(t, sub))
}

// A path outside the runtime dir is refused before anything is modified.
func TestEnsureTraversableRefusesOutsidePaths(t *testing.T) {
	withRuntimeDir(t)

	outside := t.TempDir()
	require.NoError(t, os.Chmod(outside, 0o700))

	require.Error(t, ensureTraversable(outside))
	assert.Equal(t, os.FileMode(0o700), permOf(t, outside), "a refused path must not be chmodded")
}
