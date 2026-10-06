//go:build !windows

package daemonaddr

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func listenTestSocket(t *testing.T) string {
	t.Helper()
	// Keeps the path under the macOS sun_path limit.
	dir, err := os.MkdirTemp("", "nbprobe")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	path := filepath.Join(dir, "d.sock")
	ln, err := net.Listen("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	return path
}

// The kernel refuses connect to a socket the caller may not write.
func TestDeniesCaller_SocketWithoutPermission(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses socket file permissions")
	}
	path := listenTestSocket(t)
	require.NoError(t, os.Chmod(path, 0o000))

	assert.True(t, DeniesCaller(context.Background(), "unix://"+path), "a socket the caller may not write must report a denial")
}

func TestDeniesCaller_ReachableDaemon(t *testing.T) {
	path := listenTestSocket(t)

	assert.False(t, DeniesCaller(context.Background(), "unix://"+path), "a socket that accepts the caller is not a denial")
	assert.False(t, DeniesCaller(context.Background(), "unix:"+path), "the unix:path spelling must probe the same socket")
}

// A missing or stale socket is not a denial.
func TestDeniesCaller_DaemonNotRunning(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.sock")
	assert.False(t, DeniesCaller(context.Background(), "unix://"+missing), "a missing socket is not a denial")

	dir, err := os.MkdirTemp("", "nbprobe")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	stale := filepath.Join(dir, "s.sock")
	ln, err := net.Listen("unix", stale)
	require.NoError(t, err)
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	require.NoError(t, ln.Close())
	assert.False(t, DeniesCaller(context.Background(), "unix://"+stale), "a stale socket is not a denial")
}

func TestDeniesCaller_TCPIsNeverDenied(t *testing.T) {
	assert.False(t, DeniesCaller(context.Background(), "127.0.0.1:1"), "loopback TCP cannot be group-restricted")
}
