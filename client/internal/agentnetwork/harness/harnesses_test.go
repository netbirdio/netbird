package harness

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// defHost points every harness's dir-override variable at a temp dir, never
// the real home or any credential store.
type defHost struct {
	def *Definition
	env Env
}

func newDefHost(t *testing.T, def *Definition) defHost {
	t.Helper()
	root := t.TempDir()
	dirs := map[string]string{
		"CODEX_HOME":          filepath.Join(root, "codex"),
		"XDG_CONFIG_HOME":     filepath.Join(root, "xdg"),
		"PI_CODING_AGENT_DIR": filepath.Join(root, "pi"),
		"CLAUDE_CONFIG_DIR":   filepath.Join(root, "claude"),
	}
	return defHost{def: def, env: Env{
		GOOS:       runtime.GOOS,
		Home:       filepath.Join(root, "home"),
		Getenv:     func(k string) string { return dirs[k] },
		RecordPath: filepath.Join(root, "netbird", "agent-network-setup.json"),
	}}
}

func (h defHost) files() []string {
	out := make([]string, len(h.def.Files))
	for i, f := range h.def.Files {
		out[i] = f.Path(h.env)
	}
	return out
}

func (h defHost) render(t *testing.T, variant, model string) []Setting {
	t.Helper()
	v, ok := h.def.Variant("", variant)
	require.True(t, ok, "variant %s", variant)
	if model == "" {
		model = v.DefaultModel
	}
	s, err := h.def.Render(v, map[Var]string{VarEndpoint: testEndpoint, VarModel: model}, h.env)
	require.NoError(t, err)
	return s
}

func (h defHost) plan(t *testing.T, settings []Setting, force bool) (*Plan, *Record, error) {
	t.Helper()
	rec, err := LoadRecord(h.env.RecordPath)
	require.NoError(t, err)
	p, err := NewPlan(h.def.ID, settings, rec, force)
	return p, rec, err
}

func (h defHost) apply(t *testing.T, settings []Setting, force bool) *Plan {
	t.Helper()
	p, rec, err := h.plan(t, settings, force)
	require.NoError(t, err)
	_, err = p.Apply(rec, h.env.RecordPath, testNow)
	require.NoError(t, err)
	return p
}

func writeFile(t *testing.T, file, content string, mode os.FileMode) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(file), 0o700))
	require.NoError(t, os.WriteFile(file, []byte(content), mode))
	require.NoError(t, os.Chmod(file, mode))
}

func readFile(t *testing.T, file string) string {
	t.Helper()
	data, err := os.ReadFile(file)
	require.NoError(t, err)
	return string(data)
}

// decodeFile parses a file in the harness's format, for comparing content.
func decodeFile(t *testing.T, format Format, file string) map[string]any {
	t.Helper()
	doc, err := codecFor(format).decode([]byte(readFile(t, file)))
	require.NoError(t, err)
	return doc
}

// editKey sets one key in a file the way a user would, keeping the rest.
func editKey(t *testing.T, s Setting, value any) {
	t.Helper()
	orig, err := os.ReadFile(s.File)
	if !os.IsNotExist(err) {
		require.NoError(t, err)
	}
	doc, err := codecFor(s.Format).decode(orig)
	require.NoError(t, err)
	require.NoError(t, setPath(doc, s.Path, value))
	data, err := codecFor(s.Format).encode(orig, doc)
	require.NoError(t, err)
	writeFile(t, s.File, string(data), 0o600)
}

type defVariant struct {
	def     *Definition
	variant string
	model   string
}

var defVariants = []defVariant{
	{codex, "openai", "gpt-5.5"},
	{openCode, "anthropic", ""},
	{openCode, "openai", "gpt-5.5"},
	{pi, "anthropic", "claude-opus-5"},
	{pi, "openai", ""},
}

func (v defVariant) name() string { return v.def.ID + "-" + v.variant }

// unrelated is existing content per format that setup must keep.
var unrelated = map[Format]string{
	FormatJSON: `{"theme":"dark","n":1.50,"nested":{"keep":[1,2]},"provider":{"other":{"npm":"x"}}}`,
	FormatTOML: `# Codex config, kept by hand.
approval_policy = "on-request" # ask first

[projects."/home/nico/src"]
trust_level = "trusted"

[mcp_servers.docs]
command = "npx"
args = [
  "-y", # a comment inside the array
  "docs-mcp",
]
env = { TOKEN_FILE = "~/.docs-token" }
`,
}

func TestHarnessGolden(t *testing.T) {
	for _, v := range defVariants {
		t.Run(v.name(), func(t *testing.T) {
			h := newDefHost(t, v.def)
			h.apply(t, h.render(t, v.variant, v.model), false)

			for i, file := range h.files() {
				golden := filepath.Join("testdata", v.name()+"-"+v.def.Files[i].Name)
				if *update {
					require.NoError(t, os.WriteFile(golden, []byte(readFile(t, file)), 0o644))
				}
				want, err := os.ReadFile(golden)
				require.NoError(t, err)
				assert.Equal(t, strings.ReplaceAll(string(want), "\r\n", "\n"), readFile(t, file), "%s must match its golden file", file)

				if runtime.GOOS == "windows" {
					continue
				}
				info, err := os.Stat(file)
				require.NoError(t, err)
				assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "a new config file is 0600")
			}
		})
	}
}

func TestHarnessUnrelatedKeptAndUndone(t *testing.T) {
	for _, v := range defVariants {
		t.Run(v.name(), func(t *testing.T) {
			h := newDefHost(t, v.def)
			for i, file := range h.files() {
				writeFile(t, file, unrelated[v.def.Files[i].Format], 0o600)
			}

			h.apply(t, h.render(t, v.variant, v.model), false)
			for i, file := range h.files() {
				f := v.def.Files[i]
				doc := decodeFile(t, f.Format, file)
				want := decodeDoc(t, f.Format, unrelated[f.Format])
				for k := range want {
					assert.Contains(t, doc, k, "%s keeps unrelated key %s", file, k)
				}
				if f.Format == FormatTOML {
					assert.Contains(t, readFile(t, file), "# a comment inside the array", "comments survive the edit")
				}
				backups, err := filepath.Glob(file + ".netbird-backup-*")
				require.NoError(t, err)
				assert.Len(t, backups, 1, "%s is backed up before the first write", file)
			}

			h.apply(t, nil, false)
			for i, file := range h.files() {
				f := v.def.Files[i]
				if f.Format == FormatTOML {
					assert.Equal(t, unrelated[f.Format], readFile(t, file), "undo restores the TOML byte for byte")
					continue
				}
				assert.Equal(t, decodeDoc(t, f.Format, unrelated[f.Format]), decodeFile(t, f.Format, file), "undo restores %s", file)
			}
			rec, err := LoadRecord(h.env.RecordPath)
			require.NoError(t, err)
			assert.Empty(t, rec.Harnesses, "undo drops the ownership record")
		})
	}
}

func decodeDoc(t *testing.T, format Format, content string) map[string]any {
	t.Helper()
	doc, err := codecFor(format).decode([]byte(content))
	require.NoError(t, err)
	return doc
}

func TestHarnessIdempotent(t *testing.T) {
	for _, v := range defVariants {
		t.Run(v.name(), func(t *testing.T) {
			h := newDefHost(t, v.def)
			settings := h.render(t, v.variant, v.model)
			h.apply(t, settings, false)
			var before []os.FileInfo
			for _, file := range h.files() {
				fi, err := os.Stat(file)
				require.NoError(t, err)
				before = append(before, fi)
			}

			p := h.apply(t, settings, false)
			assert.False(t, p.Pending(), "same inputs plan no write")
			assert.Empty(t, p.Changes, "same inputs plan no change")
			for i, file := range h.files() {
				fi, err := os.Stat(file)
				require.NoError(t, err)
				assert.Equal(t, before[i].ModTime(), fi.ModTime(), "%s is not rewritten", file)
			}
		})
	}
}

func TestHarnessConflictNeedsForce(t *testing.T) {
	for _, v := range defVariants {
		t.Run(v.name(), func(t *testing.T) {
			h := newDefHost(t, v.def)
			settings := h.render(t, v.variant, v.model)
			// The user already set the last key, in the last file, by hand.
			theirs := settings[len(settings)-1]
			editKey(t, theirs, "users-own")
			orig := readFile(t, theirs.File)

			p, _, err := h.plan(t, settings, false)
			require.ErrorIs(t, err, ErrConflict)
			var conflicts []string
			for _, c := range p.Changes {
				if c.Conflict {
					conflicts = append(conflicts, PathString(c.Path))
				}
			}
			assert.Equal(t, []string{PathString(theirs.Path)}, conflicts, "only the user's key conflicts")
			assert.Equal(t, orig, readFile(t, theirs.File), "a conflict writes nothing")

			h.apply(t, settings, true)
			assert.NotContains(t, readFile(t, theirs.File), "users-own", "--force overwrites")

			h.apply(t, nil, false)
			cur, present, err := getPath(decodeFile(t, theirs.Format, theirs.File), theirs.Path)
			require.NoError(t, err)
			assert.True(t, present)
			assert.Equal(t, `"users-own"`, string(cur), "undo after --force restores the user's value")
		})
	}
}

func TestHarnessUndoKeepsUserEdit(t *testing.T) {
	for _, v := range defVariants {
		t.Run(v.name(), func(t *testing.T) {
			h := newDefHost(t, v.def)
			settings := h.render(t, v.variant, v.model)
			h.apply(t, settings, false)
			edited := settings[0]
			editKey(t, edited, "edited-by-hand")

			p := h.apply(t, nil, false)
			var kept []string
			for _, c := range p.Changes {
				if c.Action == ActionKeep {
					kept = append(kept, PathString(c.Path))
				}
			}
			assert.Equal(t, []string{PathString(edited.Path)}, kept, "the edited key is reported and left alone")
			cur, _, err := getPath(decodeFile(t, edited.Format, edited.File), edited.Path)
			require.NoError(t, err)
			assert.Equal(t, `"edited-by-hand"`, string(cur), "the user's edit remains")
			for _, s := range settings[1:] {
				if s.File != edited.File {
					continue
				}
				_, present, err := getPath(decodeFile(t, s.Format, s.File), s.Path)
				require.NoError(t, err)
				assert.False(t, present, "%s is removed", PathString(s.Path))
			}
		})
	}
}

func TestHarnessModePreserved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows keeps no Unix permission bits")
	}
	for _, v := range defVariants {
		t.Run(v.name(), func(t *testing.T) {
			h := newDefHost(t, v.def)
			for i, file := range h.files() {
				writeFile(t, file, unrelated[v.def.Files[i].Format], 0o640)
			}
			h.apply(t, h.render(t, v.variant, v.model), false)
			for _, file := range h.files() {
				info, err := os.Stat(file)
				require.NoError(t, err)
				assert.Equal(t, os.FileMode(0o640), info.Mode().Perm(), "%s keeps its mode", file)
			}
		})
	}
}

func TestHarnessDryRunWritesNothing(t *testing.T) {
	for _, v := range defVariants {
		t.Run(v.name(), func(t *testing.T) {
			h := newDefHost(t, v.def)
			settings := h.render(t, v.variant, v.model)
			p, _, err := h.plan(t, settings, false)
			require.NoError(t, err)
			assert.True(t, p.Pending())
			assert.Len(t, p.Changes, len(settings), "every key is planned")
			for _, file := range h.files() {
				_, err = os.Stat(file)
				assert.True(t, os.IsNotExist(err), "planning creates no %s", file)
			}
			_, err = os.Stat(h.env.RecordPath)
			assert.True(t, os.IsNotExist(err), "planning creates no record")
		})
	}
}

func TestHarnessPaths(t *testing.T) {
	none := func(string) string { return "" }
	win := Env{GOOS: "windows", Home: `C:\Users\nico`, Getenv: none}
	linux := Env{GOOS: "linux", Home: "/home/nico", Getenv: none}
	mac := Env{GOOS: "darwin", Home: "/Users/nico", Getenv: none}
	override := func(goos, home, key, dir string) Env {
		return Env{GOOS: goos, Home: home, Getenv: func(k string) string {
			if k == key {
				return dir
			}
			return ""
		}}
	}

	cases := []struct {
		def  *Definition
		env  Env
		want []string
	}{
		{codex, win, []string{`C:\Users\nico\.codex\config.toml`}},
		{codex, linux, []string{"/home/nico/.codex/config.toml"}},
		{codex, mac, []string{"/Users/nico/.codex/config.toml"}},
		{codex, override("windows", `C:\Users\nico`, "CODEX_HOME", `D:\codex\`), []string{`D:\codex\config.toml`}},
		{openCode, win, []string{`C:\Users\nico\.config\opencode\opencode.jsonc`}},
		{openCode, mac, []string{"/Users/nico/.config/opencode/opencode.jsonc"}},
		{openCode, override("linux", "/home/nico", "XDG_CONFIG_HOME", "/xdg/"), []string{"/xdg/opencode/opencode.jsonc"}},
		{pi, win, []string{`C:\Users\nico\.pi\agent\models.json`, `C:\Users\nico\.pi\agent\settings.json`}},
		{pi, linux, []string{"/home/nico/.pi/agent/models.json", "/home/nico/.pi/agent/settings.json"}},
		{pi, override("linux", "/home/nico", "PI_CODING_AGENT_DIR", "/srv/pi"), []string{"/srv/pi/models.json", "/srv/pi/settings.json"}},
	}
	for _, tc := range cases {
		var got []string
		for _, f := range tc.def.Files {
			got = append(got, f.Path(tc.env))
		}
		assert.Equal(t, tc.want, got, "%s on %s", tc.def.ID, tc.env.GOOS)
	}
}

func TestHarnessVariants(t *testing.T) {
	_, ok := codex.Variant("anthropic_api", "anthropic")
	assert.False(t, ok, "Codex speaks only the OpenAI shape")
	for _, def := range []*Definition{codex, openCode, pi} {
		_, ok := def.Variant("bedrock_api", "")
		assert.False(t, ok, "%s cannot reach a path-routed provider", def.ID)
	}
	assert.Equal(t, []string{"claude-code", "codex", "opencode", "pi"}, func() []string {
		var ids []string
		for _, d := range All() {
			ids = append(ids, d.ID)
		}
		return ids
	}(), "setup list shows all four harnesses")
}

func TestModelEscapedInJSONValue(t *testing.T) {
	h := newDefHost(t, openCode)
	s := h.render(t, "openai", `we"ird\model`)
	frags, err := Fragments(s)
	require.NoError(t, err)
	doc := decodeDoc(t, FormatJSON, frags[h.files()[0]])
	models := doc["provider"].(map[string]any)["netbird"].(map[string]any)["models"].(map[string]any)
	assert.Contains(t, models, `we"ird\model`, "a model id with JSON metacharacters stays one key")
}

func TestPiWritesAndUndoesBothFiles(t *testing.T) {
	h := newDefHost(t, pi)
	models, settings := h.files()[0], h.files()[1]
	writeFile(t, settings, `{"theme":"dark","defaultThinkingLevel":"high"}`, 0o600)

	h.apply(t, h.render(t, "openai", "gpt-5.5"), false)
	assert.JSONEq(t, `{"providers":{"netbird":{"baseUrl":"`+testEndpoint+`/v1","api":"openai-completions","apiKey":"not-needed","models":[{"id":"gpt-5.5"}]}}}`,
		readFile(t, models), "models.json gets the provider")
	assert.JSONEq(t, `{"theme":"dark","defaultThinkingLevel":"high","defaultProvider":"netbird","defaultModel":"gpt-5.5"}`,
		readFile(t, settings), "settings.json gets the defaults")
	rec, err := LoadRecord(h.env.RecordPath)
	require.NoError(t, err)
	assert.Len(t, rec.Harnesses[pi.ID].Files, 2, "both files are recorded")
	assert.Equal(t, "configured", Status(pi.ID, rec))

	writeFile(t, models, `{}`, 0o600)
	assert.Equal(t, "configured, edited since", Status(pi.ID, rec), "an edit to either file shows")

	h.apply(t, nil, false)
	assert.JSONEq(t, `{}`, readFile(t, models), "undo empties the file it created")
	assert.JSONEq(t, `{"theme":"dark","defaultThinkingLevel":"high"}`, readFile(t, settings), "undo restores settings.json")
}

func TestPiUnparseableFileWritesNeither(t *testing.T) {
	h := newDefHost(t, pi)
	models, settings := h.files()[0], h.files()[1]
	writeFile(t, settings, "{\"theme\":\"dark\",}", 0o600)

	_, _, err := h.plan(t, h.render(t, "anthropic", ""), false)
	var perr *UnparseableError
	require.ErrorAs(t, err, &perr)
	_, err = os.Stat(models)
	assert.True(t, os.IsNotExist(err), "the parseable file is not written alone")

	frags, err := Fragments(h.render(t, "anthropic", ""))
	require.NoError(t, err)
	assert.Equal(t, []string{models, settings}, SortedFiles(frags), "printing covers both files")
}

func TestOpenCodeJSONCFallsBackToPrint(t *testing.T) {
	for name, content := range map[string]string{
		"comment":        "{\n  // my provider\n  \"$schema\": \"https://opencode.ai/config.json\"\n}",
		"trailing comma": "{\"$schema\": \"https://opencode.ai/config.json\",}",
	} {
		t.Run(name, func(t *testing.T) {
			h := newDefHost(t, openCode)
			file := h.files()[0]
			writeFile(t, file, content, 0o600)
			_, _, err := h.plan(t, h.render(t, "anthropic", ""), false)
			var perr *UnparseableError
			require.ErrorAs(t, err, &perr, "JSONC is not rewritten")
			assert.Equal(t, content, readFile(t, file))

			frags, err := Fragments(h.render(t, "anthropic", ""))
			require.NoError(t, err)
			assert.JSONEq(t, `{"model":"netbird/claude-opus-5","provider":{"netbird":{"npm":"@ai-sdk/anthropic","name":"NetBird",`+
				`"options":{"baseURL":"`+testEndpoint+`/v1","apiKey":"not-needed"},"models":{"claude-opus-5":{}}}}}`,
				frags[file], "printing still works")
		})
	}
}

func TestOpenCodeSeededFileIsEdited(t *testing.T) {
	h := newDefHost(t, openCode)
	file := h.files()[0]
	// OpenCode seeds this on first run, as strict JSON.
	seed := "{\n  \"$schema\": \"https://opencode.ai/config.json\"\n}"
	writeFile(t, file, seed, 0o600)
	h.apply(t, h.render(t, "openai", "gpt-5.5"), false)
	assert.Contains(t, readFile(t, file), `"$schema": "https://opencode.ai/config.json"`)
	h.apply(t, nil, false)
	assert.JSONEq(t, seed, readFile(t, file))
}

func TestCodexTOMLEdits(t *testing.T) {
	h := newDefHost(t, codex)
	file := h.files()[0]
	orig := `# my settings
model = "o3" # the model I like
model_reasoning_effort = "high"

[model_providers.netbird]
# my own notes on this provider
name = "NetBird"
request_max_retries = 4
`
	writeFile(t, file, orig, 0o600)
	settings := h.render(t, "openai", "gpt-5.5")

	_, _, err := h.plan(t, settings, false)
	require.ErrorIs(t, err, ErrConflict, "the user's model needs --force")

	h.apply(t, settings, true)
	assert.Equal(t, `# my settings
model = "gpt-5.5" # the model I like
model_reasoning_effort = "high"
model_provider = "netbird"

[model_providers.netbird]
# my own notes on this provider
name = "NetBird"
request_max_retries = 4
base_url = "`+testEndpoint+`/v1"
wire_api = "responses"
`, readFile(t, file), "values change in place and new keys join their table, comments kept")

	h.apply(t, nil, false)
	assert.Equal(t, orig, readFile(t, file), "undo restores the file byte for byte, the name the user wrote included")
}

func TestCodexTOMLFreshFile(t *testing.T) {
	h := newDefHost(t, codex)
	h.apply(t, h.render(t, "openai", ""), false)
	assert.Equal(t, `model_provider = "netbird"

[model_providers.netbird]
base_url = "`+testEndpoint+`/v1"
name = "NetBird"
wire_api = "responses"
`, readFile(t, h.files()[0]), "no model chosen leaves Codex its own")

	h.apply(t, nil, false)
	assert.Empty(t, readFile(t, h.files()[0]), "undo empties the file it created")
}

func TestCodexTOMLKeepsCRLF(t *testing.T) {
	h := newDefHost(t, codex)
	file := h.files()[0]
	orig := "approval_policy = \"never\"\r\n\r\n[projects.\"C:\\\\src\"]\r\ntrust_level = \"trusted\"\r\n"
	writeFile(t, file, orig, 0o600)
	h.apply(t, h.render(t, "openai", "gpt-5.5"), false)
	got := readFile(t, file)
	assert.NotContains(t, strings.ReplaceAll(got, "\r\n", ""), "\n", "every line ends in CRLF")
	h.apply(t, nil, false)
	assert.Equal(t, orig, readFile(t, file))
}

func TestCodexTOMLUnsupported(t *testing.T) {
	for name, content := range map[string]string{
		"unterminated string": "model = \"gpt\n",
		"no value":            "model =\n",
		"garbage":             "this is not toml\n",
	} {
		t.Run(name, func(t *testing.T) {
			h := newDefHost(t, codex)
			writeFile(t, h.files()[0], content, 0o600)
			_, _, err := h.plan(t, h.render(t, "openai", ""), false)
			var perr *UnparseableError
			require.ErrorAs(t, err, &perr, "a file the codec cannot read is left alone")
		})
	}
}

func TestCodexTOMLDottedTable(t *testing.T) {
	h := newDefHost(t, codex)
	file := h.files()[0]
	orig := "model_providers.netbird.name = \"NetBird\"\n"
	writeFile(t, file, orig, 0o600)
	p, rec, err := h.plan(t, h.render(t, "openai", ""), false)
	require.NoError(t, err)
	_, err = p.Apply(rec, h.env.RecordPath, testNow)
	require.Error(t, err, "a table defined by dotted keys cannot take a [header]")
	assert.Equal(t, orig, readFile(t, file), "nothing is written")
}

func TestTOMLDecodeValues(t *testing.T) {
	doc := decodeDoc(t, FormatTOML, `a = "x\ty"
b = 'C:\path'
c = 12
d = -1.5e3
e = true
f = 1979-05-27T07:32:00Z
g = 1_000
h = """
multi
"""
'quoted.key' = 1
[t."a b"]
k = [1, [2, "]"]]
[[arr]]
x = 1
`)
	assert.Equal(t, "x\ty", doc["a"])
	assert.Equal(t, `C:\path`, doc["b"])
	assert.Equal(t, `12`, string(mustCanonical(t, doc["c"])))
	assert.Equal(t, `-1.5e3`, string(mustCanonical(t, doc["d"])))
	assert.Equal(t, true, doc["e"])
	assert.Equal(t, tomlRaw("1979-05-27T07:32:00Z"), doc["f"])
	assert.Equal(t, tomlRaw("1_000"), doc["g"])
	assert.Equal(t, tomlRaw("\"\"\"\nmulti\n\"\"\""), doc["h"])
	assert.Contains(t, doc, "quoted.key")
	assert.Equal(t, tomlRaw(`[1, [2, "]"]]`), doc["t"].(map[string]any)["a b"].(map[string]any)["k"])
	assert.Equal(t, tomlRaw("[[array of tables]]"), doc["arr"])
}

func mustCanonical(t *testing.T, v any) []byte {
	t.Helper()
	c, err := canonical(v)
	require.NoError(t, err)
	return c
}

func TestDefinitionsRecordCheckedVersion(t *testing.T) {
	for _, d := range All() {
		assert.NotEmpty(t, d.CheckedVersion, "%s records the version its keys were checked against", d.ID)
		assert.NotEmpty(t, d.CAEnv, "%s names its CA variable", d.ID)
	}
}

func TestRecordRoundTripsObjectsAndHTMLCharacters(t *testing.T) {
	h := newDefHost(t, openCode)
	settings := h.render(t, "openai", "a<b>&c")
	h.apply(t, settings, false)
	rec, err := LoadRecord(h.env.RecordPath)
	require.NoError(t, err)
	assert.Equal(t, "configured", Status(openCode.ID, rec), "recorded values match the file after a save and load")
	p := h.apply(t, settings, false)
	assert.Empty(t, p.Changes, "a re-run sees its own values")
}
