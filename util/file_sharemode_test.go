package util

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadJsonShareMode_ReadsTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"SomeField": 7}`), 0o600))

	var got TestConfig
	_, err := ReadJsonShareMode(path, &got)

	require.NoError(t, err)
	assert.Equal(t, 7, got.SomeField, "the decoded value")
}

// Callers tell a missing file from a broken one to seed a default in its place,
// and the Windows path builds its own error, so the mapping has to hold there
// too.
func TestReadJsonShareMode_MissingFileIsErrNotExist(t *testing.T) {
	var got TestConfig
	_, err := ReadJsonShareMode(filepath.Join(t.TempDir(), "absent.json"), &got)

	require.Error(t, err)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestReadJsonShareMode_MalformedFileIsNotErrNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))

	var got TestConfig
	_, err := ReadJsonShareMode(path, &got)

	require.Error(t, err)
	assert.False(t, errors.Is(err, os.ErrNotExist),
		"a file that is there but unreadable must not be seeded over: %v", err)
}
