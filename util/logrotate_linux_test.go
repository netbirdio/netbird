//go:build linux

package util

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFindFirstLogrotateConflict(t *testing.T) {
	t.Run("conflict in confDir", func(t *testing.T) {
		confPath, confDir := newLogrotateLayout(t)
		conflictPath := filepath.Join(confDir, "netbird")
		writeLogrotateConfig(t, conflictPath, `/var/log/netbird/*.log {
    daily
    rotate 7
}`)
		writeLogrotateConfig(t, filepath.Join(confDir, "nginx"), `/var/log/nginx/*.log { daily }`)

		got, path := findFirstLogrotateConflictIn(confPath, confDir)
		require.True(t, got)
		require.Equal(t, conflictPath, path)
	})

	t.Run("conflict in main conf file", func(t *testing.T) {
		confPath, confDir := newLogrotateLayout(t)
		writeLogrotateConfig(t, confPath, `weekly
rotate 4
include /etc/logrotate.d
/var/log/netbird/client.log { rotate 5 }`)

		got, path := findFirstLogrotateConflictIn(confPath, confDir)
		require.True(t, got)
		require.Equal(t, confPath, path)
	})

	t.Run("no conflict when netbird is absent", func(t *testing.T) {
		confPath, confDir := newLogrotateLayout(t)
		writeLogrotateConfig(t, filepath.Join(confDir, "nginx"), `/var/log/nginx/*.log { daily }`)
		writeLogrotateConfig(t, filepath.Join(confDir, "syslog"), `/var/log/syslog { weekly }`)

		got, path := findFirstLogrotateConflictIn(confPath, confDir)
		require.False(t, got)
		require.Empty(t, path)
	})

	t.Run("commented-out netbird line is ignored", func(t *testing.T) {
		confPath, confDir := newLogrotateLayout(t)
		writeLogrotateConfig(t, filepath.Join(confDir, "misc"), `# /var/log/netbird/*.log { daily }
/var/log/other.log { weekly }`)

		got, path := findFirstLogrotateConflictIn(confPath, confDir)
		require.False(t, got)
		require.Empty(t, path)
	})

	t.Run("subdirectories in confDir are ignored", func(t *testing.T) {
		confPath, confDir := newLogrotateLayout(t)
		sub := filepath.Join(confDir, "nested")
		require.NoError(t, os.MkdirAll(sub, 0o755))
		writeLogrotateConfig(t, filepath.Join(sub, "netbird"), `/var/log/netbird/*.log { daily }`)

		got, path := findFirstLogrotateConflictIn(confPath, confDir)
		require.False(t, got)
		require.Empty(t, path)
	})

	t.Run("missing paths return no conflict", func(t *testing.T) {
		dir := t.TempDir()
		got, path := findFirstLogrotateConflictIn(
			filepath.Join(dir, "does-not-exist.conf"),
			filepath.Join(dir, "does-not-exist.d"),
		)
		require.False(t, got)
		require.Empty(t, path)
	})
}

// newLogrotateLayout creates a temp logrotate.conf path and logrotate.d dir,
// returning their paths. The conf file itself is not created.
func newLogrotateLayout(t *testing.T) (confPath, confDir string) {
	t.Helper()
	root := t.TempDir()
	confDir = filepath.Join(root, "logrotate.d")
	require.NoError(t, os.MkdirAll(confDir, 0o755))
	return filepath.Join(root, "logrotate.conf"), confDir
}

func writeLogrotateConfig(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(body), 0o644))
}
