package statemanager

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testState struct {
	Value string `json:"value"`
}

func (s *testState) Name() string { return "test_state" }

func TestInMemoryManagerNeverTouchesDisk(t *testing.T) {
	// Run from an empty directory, so a write to a relative or empty path
	// would leave a file behind here.
	dir := t.TempDir()
	t.Chdir(dir)

	m := NewInMemory()
	m.RegisterState(&testState{})
	require.NoError(t, m.UpdateState(&testState{Value: "kept"}))
	require.NoError(t, m.PersistState(context.Background()), "persisting in memory must succeed")

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Empty(t, entries, "an in-memory manager must not write a state file")

	assert.Equal(t, &testState{Value: "kept"}, m.GetState(&testState{}), "the state must still be held in memory")
	assert.NoError(t, m.LoadState(&testState{}), "loading with nothing on disk must succeed")

	names, err := m.GetSavedStateNames()
	require.NoError(t, err)
	assert.Empty(t, names, "an in-memory manager has no saved states")
}

// An empty path is a misconfiguration rather than a request for memory: the
// in-memory manager has its own constructor, so a path that resolved to
// nothing must surface instead of silently discarding every write.
func TestManagerWithoutAPathFailsToPersist(t *testing.T) {
	m := New("")
	m.RegisterState(&testState{})
	require.NoError(t, m.UpdateState(&testState{Value: "kept"}))

	assert.Error(t, m.PersistState(context.Background()),
		"an empty path must report that it cannot persist, not quietly drop the state")
}

func TestManagerPersistsToItsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")

	m := New(path)
	m.RegisterState(&testState{})
	require.NoError(t, m.UpdateState(&testState{Value: "kept"}))
	require.NoError(t, m.PersistState(context.Background()))

	names, err := New(path).GetSavedStateNames()
	require.NoError(t, err)
	assert.Equal(t, []string{"test_state"}, names, "a manager with a path must write its state there")
}
