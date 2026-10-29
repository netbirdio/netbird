package util

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"sync"
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

// The reader has to share the file for delete, or the rename cannot take
// delete access on it. Regression test.
func TestRenameFile_ReplacesAFileBeingRead(t *testing.T) {
	t.Run("a reader that shares delete", func(t *testing.T) {
		src, dst := seedReplace(t)

		f, err := openRead(dst)
		require.NoError(t, err)
		defer f.Close()

		require.Error(t, os.Rename(src, dst),
			"delete sharing alone has to be too little, or this test proves nothing")
		require.NoError(t, renameFile(src, dst), "POSIX semantics have to get the replace through")

		// The handle stays on the file it opened, so a read in flight finishes
		// on that version instead of seeing the replacement.
		held, err := io.ReadAll(f)
		require.NoError(t, err)
		assert.JSONEq(t, `{"SomeField": 1}`, string(held), "the version the reader opened")

		landed, err := os.ReadFile(dst)
		require.NoError(t, err)
		assert.JSONEq(t, `{"SomeField": 2}`, string(landed), "the version the writer put there")
	})

	t.Run("a reader that does not", func(t *testing.T) {
		src, dst := seedReplace(t)

		f, err := os.Open(dst)
		require.NoError(t, err)
		defer f.Close()

		require.Error(t, renameFile(src, dst),
			"a plain read still holds the file, and the caller is owed that error")
	})

	t.Run("no readers at all", func(t *testing.T) {
		src, dst := seedReplace(t)

		require.NoError(t, renameFile(src, dst))

		landed, err := os.ReadFile(dst)
		require.NoError(t, err)
		assert.JSONEq(t, `{"SomeField": 2}`, string(landed), "the destination holds what replaced it")
	})
}

// A config rewritten while it is being read, which is the daemon reading the
// active profile against a profile switch writing it.
func TestReadJsonWriteJson_Concurrently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, WriteJson(context.Background(), path, &TestConfig{SomeField: 1}))

	var wg sync.WaitGroup
	errs := make(chan error, 128)

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := 0; r < 50; r++ {
				var got TestConfig
				if _, err := ReadJson(path, &got); err != nil {
					errs <- err
					return
				}
			}
		}()
	}

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			for r := 0; r < 50; r++ {
				if err := WriteJson(context.Background(), path, &TestConfig{SomeField: writer}); err != nil {
					errs <- err
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		assert.NoError(t, err, "a read and a write of the same config must not collide")
	}
}
