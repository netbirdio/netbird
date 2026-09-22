package util

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// seedReplace lays out a write as writeBytes leaves it: the destination that
// exists and the temp file that is to take its place.
func seedReplace(t *testing.T) (src, dst string) {
	t.Helper()
	dir := t.TempDir()
	src = filepath.Join(dir, ".tmpstate.json")
	dst = filepath.Join(dir, "state.json")
	require.NoError(t, os.WriteFile(src, []byte(`{"SomeField": 2}`), 0o600))
	require.NoError(t, os.WriteFile(dst, []byte(`{"SomeField": 1}`), 0o600))
	return src, dst
}

// This is the failure from the field: a switch renamed its new state over the
// old file while another goroutine was reading it, and Windows refused the
// replace with "Access is denied".
func TestOpenShared_LeavesTheFileFreeToBeReplaced(t *testing.T) {
	t.Run("os.Open blocks the replace", func(t *testing.T) {
		src, dst := seedReplace(t)

		f, err := os.Open(dst)
		require.NoError(t, err)
		defer f.Close()

		require.Error(t, os.Rename(src, dst),
			"a plain read has to hold the file, or openShared is not fixing anything")
	})

	t.Run("openShared does not", func(t *testing.T) {
		src, dst := seedReplace(t)

		f, err := openShared(dst)
		require.NoError(t, err)
		defer f.Close()

		require.NoError(t, os.Rename(src, dst), "delete sharing has to let the replace through")

		// The handle stays on the file it opened, so the read in flight still
		// finishes on that version rather than seeing the replacement.
		held, err := io.ReadAll(f)
		require.NoError(t, err)
		assert.JSONEq(t, `{"SomeField": 1}`, string(held), "the version the reader opened")

		landed, err := os.ReadFile(dst)
		require.NoError(t, err)
		assert.JSONEq(t, `{"SomeField": 2}`, string(landed), "the version the writer put there")
	})
}
