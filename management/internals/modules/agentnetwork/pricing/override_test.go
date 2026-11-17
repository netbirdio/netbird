package pricing

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resetFileState snapshots and restores the package-level file state so
// tests stay order-independent.
func resetFileState(t *testing.T) {
	t.Helper()
	prevMerged := mergedTable.Load()
	fileState.mu.Lock()
	prevPath, prevMtime := fileState.path, fileState.mtime
	fileState.mu.Unlock()
	t.Cleanup(func() {
		mergedTable.Store(prevMerged)
		fileState.mu.Lock()
		fileState.path, fileState.mtime = prevPath, prevMtime
		fileState.mu.Unlock()
	})
}

func writePricing(t *testing.T, path, yml string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(yml), 0o600))
}

func TestLoadFile_MergesOverCompiledDefaults(t *testing.T) {
	resetFileState(t)
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writePricing(t, path, `
openai:
  # Reprice a built-in model. The entry replaces the built-in WHOLE:
  # omitting the cache rate here drops the built-in 0.00125 discount.
  gpt-4o:
    input_per_1k: 0.9
    output_per_1k: 1.8
  # A model NetBird doesn't know at all.
  my-private-ft:
    input_per_1k: 0.01
    output_per_1k: 0.02
    cached_input_per_1k: 0.005
gemini:
  gemini-pro:
    input_per_1k: 0.00125
    output_per_1k: 0.005
`)
	require.NoError(t, LoadFile(path, true))
	table := DefaultTable()

	gpt4o := table["openai"]["gpt-4o"]
	assert.InDelta(t, 0.9, gpt4o.InputPer1k, 1e-9, "file rate replaces the compiled-in rate")
	assert.Zero(t, gpt4o.CachedInputPer1k, "entries replace whole — omitted cache rate is dropped, not inherited")

	ft := table["openai"]["my-private-ft"]
	assert.InDelta(t, 0.005, ft.CachedInputPer1k, 1e-9, "unknown models are added to the surface")
	_, ok := table["gemini"]["gemini-pro"]
	assert.True(t, ok, "a surface the catalog doesn't declare can be added")

	// Untouched entries keep compiled-in rates (catalog, other surface,
	// supplemental).
	assert.InDelta(t, 0.00015, table["openai"]["gpt-4o-mini"].InputPer1k, 1e-9, "unlisted model keeps compiled rate")
	assert.InDelta(t, 0.003, table["anthropic"]["claude-sonnet-4-5"].InputPer1k, 1e-9, "unlisted surface untouched")
	assert.InDelta(t, 0.00125, table["openai"]["gpt-5"].InputPer1k, 1e-9, "supplemental entries untouched")

	// The synthesizer-facing lookup reads the live table too.
	e, ok := LookupDefault([]string{"openai"}, "gpt-4o")
	require.True(t, ok)
	assert.InDelta(t, 0.9, e.InputPer1k, 1e-9, "LookupDefault serves the file-backed rate")
}

func TestLoadFile_MissingPath(t *testing.T) {
	resetFileState(t)
	missing := filepath.Join(t.TempDir(), DefaultFileName)

	require.Error(t, LoadFile(missing, true),
		"explicitly configured path that doesn't exist must fail startup")

	require.NoError(t, LoadFile(missing, false),
		"conventional datadir probe tolerates an absent file (compiled-in defaults serve)")
	assert.Nil(t, mergedTable.Load(), "no file, no merged table")
	fileState.mu.Lock()
	path := fileState.path
	fileState.mu.Unlock()
	assert.Equal(t, missing, path, "the path stays registered so the reloader picks the file up when it appears")
}

func TestLoadFile_RejectsInvalid(t *testing.T) {
	resetFileState(t)
	dir := t.TempDir()
	cases := map[string]string{
		"unknown field (typo)": "openai:\n  gpt-4o:\n    input_per1k: 0.1\n",
		"negative rate":        "openai:\n  gpt-4o:\n    input_per_1k: -0.1\n",
		"non-numeric rate":     "openai:\n  gpt-4o:\n    input_per_1k: cheap\n",
		"not a mapping":        "- just\n- a\n- list\n",
	}
	for name, yml := range cases {
		path := filepath.Join(dir, DefaultFileName)
		writePricing(t, path, yml)
		assert.Error(t, LoadFile(path, true), "case %q must be rejected", name)
	}
}

// TestReload_LifeCycle drives the reloader's single-shot reload through
// its full lifecycle: file edit picked up on mtime change, a broken save
// keeps the previous table, and file removal reverts to the compiled-in
// defaults (then a re-created file loads again).
func TestReload_LifeCycle(t *testing.T) {
	resetFileState(t)
	path := filepath.Join(t.TempDir(), DefaultFileName)
	writePricing(t, path, "openai:\n  gpt-4o:\n    input_per_1k: 0.5\n    output_per_1k: 1\n")
	require.NoError(t, LoadFile(path, true))
	require.InDelta(t, 0.5, DefaultTable()["openai"]["gpt-4o"].InputPer1k, 1e-9)

	// Edit: new mtime, new rates.
	writePricing(t, path, "openai:\n  gpt-4o:\n    input_per_1k: 0.7\n    output_per_1k: 1.4\n")
	bumpMtime(t, path)
	reload()
	assert.InDelta(t, 0.7, DefaultTable()["openai"]["gpt-4o"].InputPer1k, 1e-9, "edit must be picked up")

	// Broken save: previous table survives.
	writePricing(t, path, "openai:\n  gpt-4o:\n    input_per_1k: -1\n")
	bumpMtime(t, path)
	reload()
	assert.InDelta(t, 0.7, DefaultTable()["openai"]["gpt-4o"].InputPer1k, 1e-9,
		"a malformed save must keep the previously loaded table, never blank prices")

	// Removal: compiled-in defaults serve again.
	require.NoError(t, os.Remove(path))
	reload()
	assert.InDelta(t, 0.0025, DefaultTable()["openai"]["gpt-4o"].InputPer1k, 1e-9,
		"file removal reverts to the compiled-in rate")

	// Re-created file loads without a restart.
	writePricing(t, path, "openai:\n  gpt-4o:\n    input_per_1k: 0.9\n    output_per_1k: 1.8\n")
	bumpMtime(t, path)
	reload()
	assert.InDelta(t, 0.9, DefaultTable()["openai"]["gpt-4o"].InputPer1k, 1e-9,
		"a file appearing after removal (or after a missing-probe boot) must load")
}

// bumpMtime pushes the file's mtime forward past the previously recorded
// value — timestamps can otherwise collide within the test's timescale.
func bumpMtime(t *testing.T, path string) {
	t.Helper()
	st, err := os.Stat(path)
	require.NoError(t, err)
	next := st.ModTime().Add(2 * 1e9)
	require.NoError(t, os.Chtimes(path, next, next))
}

// TestExampleYAML_InSyncWithBuiltins is the golden guard for
// defaults_llm_pricing.example.yaml: the shipped example must stay
// byte-identical to what the compiled-in table renders (catalog edits
// require `go generate ./management/internals/modules/agentnetwork/pricing`)
// and must round-trip through the same parser operators' files go
// through, reproducing the compiled-in table exactly.
func TestExampleYAML_InSyncWithBuiltins(t *testing.T) {
	onDisk, err := os.ReadFile("defaults_llm_pricing.example.yaml")
	require.NoError(t, err, "example file must exist next to the package")
	require.Equal(t, string(MarshalDefaultsYAML()), string(onDisk),
		"defaults_llm_pricing.example.yaml is stale — run: go generate ./management/internals/modules/agentnetwork/pricing")

	parsed, err := parsePricingYAML(onDisk)
	require.NoError(t, err, "the example must be a valid pricing defaults file")
	assert.Equal(t, buildDefaultTable(), parsed,
		"parsing the example must reproduce the compiled-in table exactly")
}
