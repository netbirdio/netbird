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
	assert.True(t, v.Uses(VarVertexProject), "the vertex variant references the project")

	anthropic, _ := claudeCode.Variant("anthropic", "")
	assert.False(t, anthropic.Uses(VarVertexProject), "the anthropic variant needs no project")
	assert.True(t, anthropic.Uses(VarModel), "the anthropic variant pins the model")
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

// symlinkOrSkip creates link, skipping on Windows when the user lacks the
// symlink privilege.
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o700))
	err := os.Symlink(target, link)
	if err != nil && runtime.GOOS == "windows" {
		t.Skipf("cannot create a symlink: %v", err)
	}
	require.NoError(t, err)
}

func TestSymlinkTargetWritten(t *testing.T) {
	h := newTestHost(t)
	target := filepath.Join(t.TempDir(), "dotfiles-settings.json")
	require.NoError(t, os.WriteFile(target, []byte(`{"theme":"dark"}`), 0o600))
	symlinkOrSkip(t, target, h.settings)

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

// fakeOtherUser makes every file look owned by someone other than the
// process, as under sudo, without needing root.
func fakeOtherUser(t *testing.T) {
	t.Helper()
	orig := effectiveUID
	effectiveUID = func() int { return orig() + 1 }
	t.Cleanup(func() { effectiveUID = orig })
}

func dirListing(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestOwnerMismatchRefuses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no owner uid on Windows")
	}
	h := newTestHost(t)
	h.apply(t, h.render(t, "anthropic", ""), false)
	before := h.read(t)
	listing := dirListing(t, filepath.Dir(h.settings))
	record, err := os.ReadFile(h.env.RecordPath)
	require.NoError(t, err)

	// The error names the written target, which is the resolved path (on
	// macOS t.TempDir is under /tmp, a symlink to /private/tmp).
	target, err := filepath.EvalSymlinks(h.settings)
	require.NoError(t, err)

	fakeOtherUser(t)
	for name, settings := range map[string][]Setting{
		"setup": h.render(t, "bedrock_api", ""),
		"undo":  nil,
	} {
		p, _, err := h.plan(t, settings, true)
		var notOwner *NotOwnerError
		require.ErrorAs(t, err, &notOwner, name)
		assert.Nil(t, p, "%s: no plan to apply", name)
		assert.Equal(t, target, notOwner.File, "%s: the error names the file", name)
		assert.Contains(t, err.Error(), "run setup as the file's owner", name)
	}
	assert.Equal(t, before, h.read(t), "the file is untouched")
	assert.Equal(t, listing, dirListing(t, filepath.Dir(h.settings)), "no backup or temp file")
	after, err := os.ReadFile(h.env.RecordPath)
	require.NoError(t, err)
	assert.Equal(t, string(record), string(after), "the record is untouched")
}

func TestOwnerMatchProceeds(t *testing.T) {
	h := newTestHost(t)
	h.write(t, `{"theme":"dark"}`, 0o600)
	// The real uid owns the temp file, so the check passes.
	h.apply(t, h.render(t, "anthropic", ""), false)
	assert.Contains(t, h.read(t), testEndpoint, "the owner's file gets the settings")
	assert.Len(t, h.backups(t), 1, "one backup")
}

func TestMissingFileForeignParentRefuses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no owner uid on Windows")
	}
	h := newTestHost(t)
	// Neither settings.json nor its directory exists; the nearest existing
	// parent is the test root, which looks foreign.
	root := filepath.Dir(filepath.Dir(h.settings))
	listing := dirListing(t, root)

	fakeOtherUser(t)
	p, _, err := h.plan(t, h.render(t, "anthropic", ""), false)
	var notOwner *NotOwnerError
	require.ErrorAs(t, err, &notOwner)
	assert.Nil(t, p, "no plan to apply")
	assert.Equal(t, root, notOwner.Checked, "the nearest existing parent is checked")
	assert.Contains(t, err.Error(), "does not exist", "the error says the file is missing")
	assert.Equal(t, listing, dirListing(t, root), "no directory or file created")
}

func TestDanglingSymlinkRefused(t *testing.T) {
	h := newTestHost(t)
	// A dotfiles link whose target is not checked out yet.
	missing := filepath.Join(t.TempDir(), "dotfiles", "settings.json")
	symlinkOrSkip(t, missing, h.settings)

	_, _, err := h.plan(t, h.render(t, "anthropic", ""), false)
	require.Error(t, err, "a link whose target cannot be resolved is refused")
	assert.Contains(t, err.Error(), "symlink", "the error says why")

	fi, err := os.Lstat(h.settings)
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode()&os.ModeSymlink, "the link is left in place")
	_, err = os.Stat(missing)
	assert.True(t, os.IsNotExist(err), "nothing is written through the link")
}

func TestInvalidUTF8IsUnparseable(t *testing.T) {
	h := newTestHost(t)
	orig := "{\"theme\":\"caf\xe9\"}"
	h.write(t, orig, 0o600)

	_, _, err := h.plan(t, h.render(t, "anthropic", ""), false)
	var perr *UnparseableError
	require.ErrorAs(t, err, &perr, "invalid UTF-8 would be rewritten as U+FFFD")
	assert.Equal(t, orig, h.read(t), "the file is untouched")
}

func TestRecordNullEntries(t *testing.T) {
	h := newTestHost(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(h.env.RecordPath), 0o700))

	// A null harness is the same as no harness.
	require.NoError(t, os.WriteFile(h.env.RecordPath, []byte(`{"harnesses":{"claude-code":null}}`), 0o600))
	rec, err := LoadRecord(h.env.RecordPath)
	require.NoError(t, err)
	assert.Equal(t, "not configured", Status(claudeCode.ID, rec))
	_, err = NewPlan(claudeCode.ID, h.render(t, "anthropic", ""), rec, false)
	assert.NoError(t, err, "a null harness plans like an empty record")

	// A null file entry loses which keys NetBird owns, so it is refused
	// instead of panicking later.
	require.NoError(t, os.WriteFile(h.env.RecordPath, []byte(`{"harnesses":{"claude-code":{"files":{"/x":null}}}}`), 0o600))
	_, err = LoadRecord(h.env.RecordPath)
	require.Error(t, err)
	assert.Contains(t, err.Error(), h.env.RecordPath, "the error names the record")
}

func TestKeepOnlyPlanReleasesOwnership(t *testing.T) {
	h := newTestHost(t)
	h.apply(t, h.render(t, "anthropic", "claude-opus-5"), false)
	h.write(t, strings.Replace(h.read(t), `"claude-opus-5"`, `"claude-haiku-4-5"`, 1), 0o600)

	// Rerun without a model: NetBird no longer wants "model", and the user
	// changed it, so the only change is a keep.
	p := h.apply(t, h.render(t, "anthropic", ""), false)
	require.Len(t, p.Changes, 1, "one change planned")
	assert.Equal(t, ActionKeep, p.Changes[0].Action, "the edited key is kept")
	assert.True(t, p.Pending(), "releasing a key updates the record, so the plan is pending")

	rec, err := LoadRecord(h.env.RecordPath)
	require.NoError(t, err)
	for _, fr := range rec.Harnesses[claudeCode.ID].Files {
		for _, k := range fr.Keys {
			assert.NotEqual(t, "model", PathString(k.Path), "the kept key is no longer NetBird's")
		}
	}
	assert.Equal(t, "configured", Status(claudeCode.ID, rec), "the remaining keys are as written")
}

func TestRelativeConfigDirResolved(t *testing.T) {
	t.Chdir(t.TempDir())
	cwd, err := os.Getwd()
	require.NoError(t, err)
	rel := func(k string) string {
		if k == "CLAUDE_CONFIG_DIR" {
			return "cfg"
		}
		return ""
	}
	f := claudeCode.Files[0]

	assert.Equal(t, filepath.Join(cwd, "cfg", "settings.json"),
		f.Path(Env{GOOS: runtime.GOOS, Home: cwd, Getenv: rel}),
		"a relative dir is recorded as the absolute path undo will find")

	other, sep := "windows", `\`
	if runtime.GOOS == "windows" {
		other, sep = "linux", "/"
	}
	assert.Equal(t, "cfg"+sep+"settings.json", f.Path(Env{GOOS: other, Home: "/h", Getenv: rel}),
		"another OS's path is not resolved against this host's working directory")
}

// blockDir replaces dir with a regular file, so creating anything under it
// fails even for root.
func blockDir(t *testing.T, dir string) {
	t.Helper()
	require.NoError(t, os.RemoveAll(dir))
	require.NoError(t, os.MkdirAll(filepath.Dir(dir), 0o700))
	require.NoError(t, os.WriteFile(dir, nil, 0o600))
}

func TestApplyRollsBackWhenRecordSaveFails(t *testing.T) {
	for name, orig := range map[string]string{"existing file": `{"theme":"dark"}`, "new file": ""} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t)
			if orig != "" {
				h.write(t, orig, 0o600)
			}
			p, rec, err := h.plan(t, h.render(t, "anthropic", "claude-opus-5"), false)
			require.NoError(t, err)

			recDir := filepath.Join(t.TempDir(), "netbird")
			blockDir(t, recDir)
			backups, err := p.Apply(rec, filepath.Join(recDir, "agent-network-setup.json"), testNow)
			require.Error(t, err, "the record cannot be saved")

			if orig != "" {
				assert.Equal(t, orig, h.read(t), "the settings file is restored")
			} else {
				_, err := os.Stat(h.settings)
				assert.True(t, os.IsNotExist(err), "the settings file setup created is removed")
			}
			assert.Empty(t, backups, "no backup is reported")
			assert.Empty(t, h.backups(t), "the backup went back into place")
			assert.Empty(t, rec.Harnesses, "the in-memory record is unchanged")
		})
	}
}

func TestApplyRollsBackEarlierFiles(t *testing.T) {
	h := newTestHost(t)
	root := t.TempDir()
	first := filepath.Join(root, "a", "settings.json")
	second := filepath.Join(root, "b", "settings.json")
	require.NoError(t, os.MkdirAll(filepath.Dir(first), 0o700))
	orig := `{"theme":"dark"}`
	require.NoError(t, os.WriteFile(first, []byte(orig), 0o600))

	settings := []Setting{
		{File: first, Format: FormatJSON, Path: []string{"k"}, Value: "v"},
		{File: second, Format: FormatJSON, Path: []string{"k"}, Value: "v"},
	}
	p, rec, err := h.plan(t, settings, false)
	require.NoError(t, err)

	// The second file's directory cannot be created once planning is done.
	blockDir(t, filepath.Dir(second))
	_, err = p.Apply(rec, h.env.RecordPath, testNow)
	require.Error(t, err, "the second write fails")

	data, err := os.ReadFile(first)
	require.NoError(t, err)
	assert.Equal(t, orig, string(data), "the first file is restored")
	backups, err := filepath.Glob(first + ".netbird-backup-*")
	require.NoError(t, err)
	assert.Empty(t, backups, "the backup went back into place")
	_, err = os.Stat(h.env.RecordPath)
	assert.True(t, os.IsNotExist(err), "no record is written")
}
