package util

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

// TestSetupLogFile_RotatesOnSize drives >MaxSize bytes through the writer
// returned by setupLogFile and asserts a backup file appears.
func TestSetupLogFile_RotatesOnSize(t *testing.T) {
	t.Setenv("NB_LOG_MAX_SIZE_MB", "1")

	dir := t.TempDir()
	logPath := filepath.Join(dir, "netbird.log")

	w, err := setupLogFile(logPath, false)
	require.NoError(t, err)
	t.Cleanup(func() {
		if c, ok := w.(io.Closer); ok {
			_ = c.Close()
		}
	})

	chunk := []byte(strings.Repeat("x", 64*1024) + "\n")
	for range 20 {
		_, err := w.Write(chunk)
		require.NoError(t, err)
	}

	info, err := os.Stat(logPath)
	require.NoError(t, err)
	require.Less(t, info.Size(), int64(1<<20),
		"active log should be < 1 MB after rotation, got %d", info.Size())

	require.Eventually(t, func() bool {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			name := e.Name()
			if name == filepath.Base(logPath) {
				continue
			}
			if strings.HasPrefix(name, "netbird-") && strings.HasSuffix(name, ".log.gz") {
				return true
			}
		}
		return false
	}, 5*time.Second, 50*time.Millisecond, "expected a rotated backup file in %s", dir)
}

// TestSetupLogFile_RotationDisabled verifies that with rotation off, the file
// grows past MaxSize and no backups are created.
func TestSetupLogFile_RotationDisabled(t *testing.T) {
	t.Setenv("NB_LOG_MAX_SIZE_MB", "1")

	dir := t.TempDir()
	logPath := filepath.Join(dir, "netbird.log")

	w, err := setupLogFile(logPath, true)
	require.NoError(t, err)

	f, ok := w.(*os.File)
	require.True(t, ok, "expected plain *os.File when rotation is disabled, got %T", w)
	t.Cleanup(func() { _ = f.Close() })

	chunk := []byte(strings.Repeat("y", 64*1024) + "\n")
	for range 20 {
		_, err := w.Write(chunk)
		require.NoError(t, err)
	}

	info, err := os.Stat(logPath)
	require.NoError(t, err)
	require.GreaterOrEqual(t, info.Size(), int64(1<<20),
		"file should exceed MaxSize when rotation is disabled, got %d", info.Size())

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "no backup files should exist when rotation is disabled, got %v", entries)
}

// TestIsRotationDisabled_EnvFlag covers the NB_LOG_DISABLE_ROTATION env path.
// The logrotate-conflict branch is exercised separately on linux.
func TestIsRotationDisabled_EnvFlag(t *testing.T) {
	logger := log.New()
	logger.SetOutput(io.Discard)

	t.Setenv("NB_LOG_DISABLE_ROTATION", "true")
	require.True(t, isRotationDisabled(logger))
}
