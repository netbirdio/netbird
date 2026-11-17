package util

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadJson_ReadsTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"SomeField": 7}`), 0o600))

	var got TestConfig
	_, err := ReadJson(path, &got)

	require.NoError(t, err)
	assert.Equal(t, 7, got.SomeField, "the decoded value")
}

// Callers tell a missing file from a broken one so they can seed a default in
// its place. The Windows path opens through a root and rebuilds the error, so
// the mapping has to survive that.
func TestReadJson_MissingFileIsErrNotExist(t *testing.T) {
	dir := t.TempDir()

	for _, tc := range []struct {
		name string
		path string
	}{
		{"missing file", filepath.Join(dir, "absent.json")},
		{"missing directory", filepath.Join(dir, "absent", "absent.json")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got TestConfig
			_, err := ReadJson(tc.path, &got)

			require.Error(t, err)
			assert.ErrorIs(t, err, os.ErrNotExist)
			assert.Contains(t, err.Error(), tc.path, "the error names the file the caller asked for")
		})
	}
}

func TestReadJson_MalformedFileIsNotErrNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))

	var got TestConfig
	_, err := ReadJson(path, &got)

	require.Error(t, err)
	assert.False(t, errors.Is(err, os.ErrNotExist),
		"a file that is there but unreadable must not be seeded over: %v", err)
}
