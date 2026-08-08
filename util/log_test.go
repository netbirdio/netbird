package util

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
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

// TestNewRotatedOutputCreatesMissingParentDir verifies that newRotatedOutput
// creates the parent directory of the log file if it does not yet exist, so
// the daemon can produce log output on first start without requiring a prior
// `netbird service install` to have created /var/log/netbird. Fixes #4392.
func TestNewRotatedOutputCreatesMissingParentDir(t *testing.T) {
	tempDir := t.TempDir()
	// nest the log file two levels below tempDir, so neither "logs" nor
	// "netbird" exist at the time newRotatedOutput is called.
	logPath := filepath.Join(tempDir, "logs", "netbird", "client.log")

	// sanity: parent dir must NOT exist yet
	parent := filepath.Dir(logPath)
	_, err := os.Stat(parent)
	require.True(t, os.IsNotExist(err), "test precondition: parent dir must not exist yet, got err=%v", err)

	w := newRotatedOutput(logPath)
	require.NotNil(t, w, "newRotatedOutput should return a non-nil writer")

	// after construction, the parent directory should have been created
	info, err := os.Stat(parent)
	require.NoError(t, err, "parent directory should exist after newRotatedOutput")
	assert.True(t, info.IsDir(), "parent path should be a directory")

	// writing to the returned writer should succeed (lumberjack opens the
	// file lazily on first write — no parent-missing error any more)
	n, err := w.Write([]byte("test entry\n"))
	require.NoError(t, err, "write to rotated output should succeed")
	assert.Greater(t, n, 0)

	// file should now exist with our content
	content, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Equal(t, "test entry\n", string(content))
}

// TestNewRotatedOutputWithExistingParentDir verifies the function is a no-op
// when the parent directory already exists.
func TestNewRotatedOutputWithExistingParentDir(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "client.log")

	w := newRotatedOutput(logPath)
	require.NotNil(t, w)

	// tempDir should still exist and be a directory
	info, err := os.Stat(tempDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())

	n, err := w.Write([]byte("ok\n"))
	require.NoError(t, err)
	assert.Greater(t, n, 0)
}

// TestNewRotatedOutputWithRootOrCwdParentDoesNotPanic verifies the function
// silently skips MkdirAll for path values whose Dir() would resolve to the
// current working directory or the filesystem root, so we never accidentally
// try to "create" "/" or ".".
func TestNewRotatedOutputWithRootOrCwdParentDoesNotPanic(t *testing.T) {
	// filepath.Dir("client.log") returns "." which we want to skip
	w := newRotatedOutput("client.log")
	require.NotNil(t, w)
	// We deliberately don't write to the writer here because writing would
	// create a file in the test's working directory; the assertion is only
	// that newRotatedOutput returns without panicking and doesn't try to
	// MkdirAll(".", ...) which would be a no-op anyway but is wasteful.
}
