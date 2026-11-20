package harness

// openCodeKeys mirrors the dashboard's OpenCode snippet: the AI SDK package
// for the provider's API shape, the /v1 base, and a placeholder key the SDKs
// insist on.
func openCodeKeys(npm string) []Key {
	return []Key{
		{Path: []string{"model"}, Value: "netbird/{model}"},
		{Path: []string{"provider", "netbird", "npm"}, Value: npm},
		{Path: []string{"provider", "netbird", "name"}, Value: "NetBird"},
		{Path: []string{"provider", "netbird", "options", "baseURL"}, Value: "{endpoint}/v1"},
		{Path: []string{"provider", "netbird", "options", "apiKey"}, Value: "not-needed"},
		{Path: []string{"provider", "netbird", "models"}, Value: `{"{model}":{}}`, JSON: true},
	}
}

// openCode writes opencode.jsonc in the global config dir, which xdg-basedir
// puts under XDG_CONFIG_HOME or ~/.config on every OS, Windows included.
// OpenCode merges config.json, opencode.json and opencode.jsonc in that order
// and seeds opencode.jsonc on first run, so that file is the one whose keys
// win. Verified against the source of v1.19.5 (packages/core/src/global.ts,
// packages/opencode/src/config/config.ts).
var openCode = &Definition{
	ID:             "opencode",
	Name:           "OpenCode",
	CheckedVersion: "1.19.5",
	Files: []File{{
		DirEnv:       "XDG_CONFIG_HOME",
		DirEnvSuffix: "opencode",
		Dir:          ".config/opencode",
		Name:         "opencode.jsonc",
		Format:       FormatJSON,
	}},
	Variants: map[string]Variant{
		"anthropic": {DefaultModel: "claude-opus-5", Keys: openCodeKeys("@ai-sdk/anthropic")},
		"openai":    {DefaultModel: "gpt-5.5", Keys: openCodeKeys("@ai-sdk/openai-compatible")},
	},
	Notice: "OpenCode now defaults to the netbird provider; a project's own opencode.json can still pick another. " +
		"Run `netbird agent-network setup undo opencode` to switch back.",
	// OpenCode runs on Bun, which reads Node's variable.
	CAEnv: "NODE_EXTRA_CA_CERTS",
}
