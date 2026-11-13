package harness

import (
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var update = flag.Bool("update", false, "rewrite the golden files")

const testEndpoint = "https://an.example.netbird.test"

var testNow = time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)

type testHost struct {
	env      Env
	settings string
}

// newTestHost points Claude Code at a temp CLAUDE_CONFIG_DIR, never the real
// home.
func newTestHost(t *testing.T) testHost {
	t.Helper()
	root := t.TempDir()
	cfgDir := filepath.Join(root, "claude")
	env := Env{
		GOOS: runtime.GOOS,
		Home: filepath.Join(root, "home"),
		Getenv: func(k string) string {
			if k == "CLAUDE_CONFIG_DIR" {
				return cfgDir
			}
			return ""
		},
		RecordPath: filepath.Join(root, "netbird", "agent-network-setup.json"),
	}
	return testHost{env: env, settings: filepath.Join(cfgDir, "settings.json")}
}

func (h testHost) render(t *testing.T, variant, model string) []Setting {
	t.Helper()
	v, ok := claudeCode.Variant(variant, "")
	require.True(t, ok, "variant %s", variant)
	if model == "" {
		model = v.DefaultModel
	}
	s, err := claudeCode.Render(v, map[Var]string{
		VarEndpoint:      testEndpoint,
		VarModel:         model,
		VarVertexProject: "my-gcp-project",
	}, h.env)
	require.NoError(t, err)
	return s
}

func (h testHost) plan(t *testing.T, settings []Setting, force bool) (*Plan, *Record, error) {
	t.Helper()
	rec, err := LoadRecord(h.env.RecordPath)
	require.NoError(t, err)
	p, err := NewPlan(claudeCode.ID, settings, rec, force)
	return p, rec, err
}

func (h testHost) apply(t *testing.T, settings []Setting, force bool) *Plan {
	t.Helper()
	p, rec, err := h.plan(t, settings, force)
	require.NoError(t, err)
	_, err = p.Apply(rec, h.env.RecordPath, testNow)
	require.NoError(t, err)
	return p
}

func (h testHost) undo(t *testing.T) *Plan {
	t.Helper()
	return h.apply(t, nil, false)
}

func (h testHost) write(t *testing.T, content string, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(h.settings), 0o700))
	require.NoError(t, os.WriteFile(h.settings, []byte(content), mode))
	require.NoError(t, os.Chmod(h.settings, mode))
}

func (h testHost) read(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(h.settings)
	require.NoError(t, err)
	return string(data)
}

func (h testHost) backups(t *testing.T) []string {
	t.Helper()
	m, err := filepath.Glob(h.settings + ".netbird-backup-*")
	require.NoError(t, err)
	return m
}

var variants = []struct{ id, model string }{
	{"anthropic", "claude-opus-5"},
	{"bedrock_api", "eu.anthropic.claude-sonnet-4-5-20250929-v1:0"},
	{"vertex_ai_api", "claude-sonnet-4-5"},
	{"kimi_api", ""},
}

func TestGoldenMissingFile(t *testing.T) {
	for _, v := range variants {
		t.Run(v.id, func(t *testing.T) {
			h := newTestHost(t)
			h.apply(t, h.render(t, v.id, v.model), false)

			golden := filepath.Join("testdata", "claude-code-"+v.id+".json")
			if *update {
				require.NoError(t, os.WriteFile(golden, []byte(h.read(t)), 0o644))
			}
			want, err := os.ReadFile(golden)
			require.NoError(t, err)
			// A Windows checkout may turn the golden file's line endings into CRLF.
			assert.Equal(t, strings.ReplaceAll(string(want), "\r\n", "\n"), h.read(t), "rendered settings must match the golden file")
			assert.Empty(t, h.backups(t), "nothing to back up when the file did not exist")

			if runtime.GOOS == "windows" {
				return
			}
			info, err := os.Stat(h.settings)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "a new settings file is 0600")
			dir, err := os.Stat(filepath.Dir(h.settings))
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0o700), dir.Mode().Perm(), "a new config dir is 0700")
		})
	}
}

func TestModelOmittedWhenNoneChosen(t *testing.T) {
	h := newTestHost(t)
	for _, s := range h.render(t, "anthropic", "") {
		assert.NotEqual(t, "model", PathString(s.Path), "no model chosen leaves Claude Code's own default")
	}
}

func TestVertexNeedsProject(t *testing.T) {
	h := newTestHost(t)
	v, _ := claudeCode.Variant("vertex_ai_api", "")
	_, err := claudeCode.Render(v, map[Var]string{VarEndpoint: testEndpoint}, h.env)
	var missing *MissingVarError
	require.ErrorAs(t, err, &missing)
	assert.Equal(t, VarVertexProject, missing.Var)
}

func TestVariantFallsBackToFlavor(t *testing.T) {
	_, ok := claudeCode.Variant("anthropic_api", "anthropic")
	assert.True(t, ok, "an anthropic-flavored provider uses the anthropic keys")
	_, ok = claudeCode.Variant("openai_api", "openai")
	assert.False(t, ok, "Claude Code cannot speak the OpenAI shape")
}

func TestUnrelatedKeysKeptAndUndone(t *testing.T) {
	for _, v := range variants {
		t.Run(v.id, func(t *testing.T) {
			h := newTestHost(t)
			orig := `{"theme":"dark","env":{"FOO":"bar"},"permissions":{"allow":["Bash(ls:*)"]},"n":1.50}`
			h.write(t, orig, 0o640)

			h.apply(t, h.render(t, v.id, v.model), false)
			got := h.read(t)
			assert.Contains(t, got, `"theme": "dark"`, "unrelated keys survive")
			assert.Contains(t, got, `"FOO": "bar"`, "unrelated env vars survive")
			assert.Contains(t, got, `"Bash(ls:*)"`, "nested unrelated values survive")
			assert.Contains(t, got, `"n": 1.50`, "numbers keep their spelling")
			require.Len(t, h.backups(t), 1, "the first write backs the file up")
			backup, err := os.ReadFile(h.backups(t)[0])
			require.NoError(t, err)
			assert.Equal(t, orig, string(backup), "the backup holds the original bytes")

			h.undo(t)
			doc, err := decodeJSONDoc([]byte(h.read(t)))
			require.NoError(t, err)
			want, err := decodeJSONDoc([]byte(orig))
			require.NoError(t, err)
			assert.Equal(t, want, doc, "undo returns the file to its original content")

			rec, err := LoadRecord(h.env.RecordPath)
			require.NoError(t, err)
			assert.Empty(t, rec.Harnesses, "undo drops the ownership record")
		})
	}
}

func TestIdempotentRerun(t *testing.T) {
	h := newTestHost(t)
	h.write(t, `{"theme":"dark"}`, 0o600)
	settings := h.render(t, "anthropic", "claude-opus-5")
	h.apply(t, settings, false)
	first := h.read(t)
	before, err := os.Stat(h.settings)
	require.NoError(t, err)

	p := h.apply(t, settings, false)
	assert.False(t, p.Pending(), "same inputs plan no write")
	assert.Empty(t, p.Changes, "same inputs plan no change")
	after, err := os.Stat(h.settings)
	require.NoError(t, err)
	assert.Equal(t, before.ModTime(), after.ModTime(), "the file is not rewritten")
	assert.Equal(t, first, h.read(t))
	assert.Len(t, h.backups(t), 1, "a re-run makes no new backup")
}

func TestConflictNeedsForce(t *testing.T) {
	h := newTestHost(t)
	orig := `{"apiKeyHelper":"~/bin/get-key.sh","env":{"ANTHROPIC_BASE_URL":"https://corp-gateway.example"}}`
	h.write(t, orig, 0o600)
	settings := h.render(t, "anthropic", "")

	p, _, err := h.plan(t, settings, false)
	require.ErrorIs(t, err, ErrConflict)
	var conflicts []string
	for _, c := range p.Changes {
		if c.Conflict {
			conflicts = append(conflicts, PathString(c.Path)+"="+string(c.Before))
		}
	}
	assert.ElementsMatch(t, []string{
		`apiKeyHelper="~/bin/get-key.sh"`,
		`env.ANTHROPIC_BASE_URL="https://corp-gateway.example"`,
	}, conflicts, "the conflicting values are shown")
	assert.Equal(t, orig, h.read(t), "a conflict writes nothing")

	h.apply(t, settings, true)
	assert.Contains(t, h.read(t), testEndpoint, "--force overwrites")

	h.undo(t)
	doc, err := decodeJSONDoc([]byte(h.read(t)))
	require.NoError(t, err)
	want, _ := decodeJSONDoc([]byte(orig))
	assert.Equal(t, want, doc, "undo after --force restores the user's values")
}

func TestUndoKeepsUserEdit(t *testing.T) {
	h := newTestHost(t)
	h.apply(t, h.render(t, "anthropic", "claude-opus-5"), false)

	// The user picks another model by hand after setup.
	edited := strings.Replace(h.read(t), `"claude-opus-5"`, `"claude-haiku-4-5"`, 1)
	h.write(t, edited, 0o600)

	p := h.undo(t)
	var kept []string
	for _, c := range p.Changes {
		if c.Action == ActionKeep {
			kept = append(kept, PathString(c.Path))
		}
	}
	assert.Equal(t, []string{"model"}, kept, "the edited key is reported and left alone")
	doc, err := decodeJSONDoc([]byte(h.read(t)))
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"model": "claude-haiku-4-5"}, doc, "only the user's edit remains")
	rec, err := LoadRecord(h.env.RecordPath)
	require.NoError(t, err)
	assert.Empty(t, rec.Harnesses, "the kept key is no longer NetBird's")
}

func TestRerunAfterUserEditIsConflict(t *testing.T) {
	h := newTestHost(t)
	h.write(t, `{"model":"claude-sonnet-4-5"}`, 0o600)
	h.apply(t, h.render(t, "anthropic", "claude-opus-5"), true)
	h.write(t, strings.Replace(h.read(t), `"claude-opus-5"`, `"claude-haiku-4-5"`, 1), 0o600)

	_, _, err := h.plan(t, h.render(t, "anthropic", "claude-opus-5"), false)
	require.ErrorIs(t, err, ErrConflict, "a value the user set over ours is theirs")

	h.apply(t, h.render(t, "anthropic", "claude-opus-5"), true)
	h.undo(t)
	assert.JSONEq(t, `{"model":"claude-haiku-4-5"}`, h.read(t), "undo restores the user's latest value")
}

func TestSwitchingVariantReleasesOldKeys(t *testing.T) {
	h := newTestHost(t)
	h.write(t, `{"apiKeyHelper":"mine"}`, 0o600)
	h.apply(t, h.render(t, "anthropic", "claude-opus-5"), true)
	h.apply(t, h.render(t, "bedrock_api", "m"), false)

	doc, err := decodeJSONDoc([]byte(h.read(t)))
	require.NoError(t, err)
	assert.Equal(t, "mine", doc["apiKeyHelper"], "the anthropic-only key goes back to the user's value")
	assert.NotContains(t, doc, "model", "the anthropic-only model key is removed")
	assert.Equal(t, "1", doc["env"].(map[string]any)["CLAUDE_CODE_USE_BEDROCK"])

	h.undo(t)
	assert.JSONEq(t, `{"apiKeyHelper":"mine"}`, h.read(t))
}

func TestModePreserved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows keeps no Unix permission bits")
	}
	h := newTestHost(t)
	h.write(t, `{}`, 0o640)
	h.apply(t, h.render(t, "anthropic", ""), false)

	info, err := os.Stat(h.settings)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), info.Mode().Perm(), "the existing mode is kept")
	backup, err := os.Stat(h.backups(t)[0])
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o640), backup.Mode().Perm(), "the backup keeps the mode")
}

func TestSymlinkTargetWritten(t *testing.T) {
	h := newTestHost(t)
	target := filepath.Join(t.TempDir(), "dotfiles-settings.json")
	require.NoError(t, os.WriteFile(target, []byte(`{"theme":"dark"}`), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Dir(h.settings), 0o700))
	require.NoError(t, os.Symlink(target, h.settings))

	h.apply(t, h.render(t, "anthropic", ""), false)
	fi, err := os.Lstat(h.settings)
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode()&os.ModeSymlink, "the symlink stays a symlink")
	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Contains(t, string(data), testEndpoint, "the link target gets the settings")
}

func TestDryRunWritesNothing(t *testing.T) {
	h := newTestHost(t)
	p, _, err := h.plan(t, h.render(t, "anthropic", "claude-opus-5"), false)
	require.NoError(t, err)
	assert.True(t, p.Pending())
	assert.Len(t, p.Changes, 3, "three keys to set")
	_, err = os.Stat(h.settings)
	assert.True(t, os.IsNotExist(err), "planning creates no settings file")
	_, err = os.Stat(h.env.RecordPath)
	assert.True(t, os.IsNotExist(err), "planning creates no record")
}

func TestUnparseableFile(t *testing.T) {
	h := newTestHost(t)
	h.write(t, "{\n  // my comment\n  \"theme\": \"dark\"\n}", 0o600)
	_, _, err := h.plan(t, h.render(t, "anthropic", ""), false)
	var perr *UnparseableError
	require.ErrorAs(t, err, &perr, "a commented file is not rewritten")

	frags, err := Fragments(h.render(t, "anthropic", "claude-opus-5"))
	require.NoError(t, err)
	assert.JSONEq(t, `{"apiKeyHelper":"echo '-'","model":"claude-opus-5","env":{"ANTHROPIC_BASE_URL":"`+testEndpoint+`"}}`,
		frags[h.settings], "printing still works")
}

func TestPathResolution(t *testing.T) {
	f := claudeCode.Files[0]
	none := func(string) string { return "" }

	assert.Equal(t, `C:\Users\nico\.claude\settings.json`,
		f.Path(Env{GOOS: "windows", Home: `C:\Users\nico`, Getenv: none}), "Windows uses %USERPROFILE%")
	assert.Equal(t, "/home/nico/.claude/settings.json",
		f.Path(Env{GOOS: "linux", Home: "/home/nico", Getenv: none}))
	assert.Equal(t, "/Users/nico/.claude/settings.json",
		f.Path(Env{GOOS: "darwin", Home: "/Users/nico", Getenv: none}))
	assert.Equal(t, `D:\cfg\claude\settings.json`,
		f.Path(Env{GOOS: "windows", Home: `C:\Users\nico`, Getenv: func(k string) string {
			if k == "CLAUDE_CONFIG_DIR" {
				return `D:\cfg\claude\`
			}
			return ""
		}}), "CLAUDE_CONFIG_DIR replaces the directory")
}

func TestStatus(t *testing.T) {
	h := newTestHost(t)
	rec, err := LoadRecord(h.env.RecordPath)
	require.NoError(t, err)
	assert.Equal(t, "not configured", Status(claudeCode.ID, rec))

	h.apply(t, h.render(t, "anthropic", "claude-opus-5"), false)
	rec, err = LoadRecord(h.env.RecordPath)
	require.NoError(t, err)
	assert.Equal(t, "configured", Status(claudeCode.ID, rec))

	h.write(t, `{}`, 0o600)
	assert.Equal(t, "configured, edited since", Status(claudeCode.ID, rec))
}
