package harness

// codex mirrors the dashboard's Codex snippet. Codex ignores OPENAI_BASE_URL,
// so the endpoint is a model provider of its own. It sets no env_key and
// requires_openai_auth defaults to false, so Codex sends no credential and
// shows no login screen for it. Verified against the source of rust-v0.167.0
// (codex-rs/model-provider-info, codex-rs/utils/home-dir).
var codex = &Definition{
	ID:             "codex",
	Name:           "Codex",
	CheckedVersion: "0.167.0",
	Files: []File{{
		DirEnv: "CODEX_HOME",
		Dir:    ".codex",
		Name:   "config.toml",
		Format: FormatTOML,
	}},
	Variants: map[string]Variant{
		"openai": {Keys: []Key{
			{Path: []string{"model"}, Value: "{model}"},
			{Path: []string{"model_provider"}, Value: "netbird"},
			{Path: []string{"model_providers", "netbird", "name"}, Value: "NetBird"},
			{Path: []string{"model_providers", "netbird", "base_url"}, Value: "{endpoint}/v1"},
			{Path: []string{"model_providers", "netbird", "wire_api"}, Value: "responses"},
		}},
	},
	Notice: "While these settings are in place, Codex sends its requests to Agent Networks " +
		"instead of your ChatGPT login or OpenAI API key, which stay saved; " +
		"run `netbird agent-network setup undo codex` to switch back.",
	CAEnv: "CODEX_CA_CERTIFICATE",
}
