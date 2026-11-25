package harness

const (
	piModels = iota
	piSettings
)

// piKeys mirrors the dashboard's pi snippets: a provider in models.json and
// the startup default in settings.json. pi appends the API path itself, and
// keeps a provider's models unavailable without an apiKey.
func piKeys(baseURL, api string) []Key {
	return []Key{
		{File: piModels, Path: []string{"providers", "netbird", "baseUrl"}, Value: baseURL},
		{File: piModels, Path: []string{"providers", "netbird", "api"}, Value: api},
		{File: piModels, Path: []string{"providers", "netbird", "apiKey"}, Value: "not-needed"},
		{File: piModels, Path: []string{"providers", "netbird", "models"}, Value: `[{"id":"{model}"}]`, JSON: true},
		{File: piSettings, Path: []string{"defaultProvider"}, Value: "netbird"},
		{File: piSettings, Path: []string{"defaultModel"}, Value: "{model}"},
	}
}

// pi is @earendil-works/pi-coding-agent. Its agent dir is ~/.pi/agent on
// every OS (os.homedir), or PI_CODING_AGENT_DIR. Verified against the 1.5.0
// package (dist/config.js, docs/models-configuration.md, docs/settings.md).
var pi = &Definition{
	ID:             "pi",
	Name:           "Pi",
	CheckedVersion: "1.5.0",
	Files: []File{
		piModels:   {DirEnv: "PI_CODING_AGENT_DIR", Dir: ".pi/agent", Name: "models.json", Format: FormatJSON},
		piSettings: {DirEnv: "PI_CODING_AGENT_DIR", Dir: ".pi/agent", Name: "settings.json", Format: FormatJSON},
	},
	Variants: map[string]Variant{
		"anthropic": {DefaultModel: "claude-opus-5", Keys: piKeys("{endpoint}", "anthropic-messages")},
		"openai":    {DefaultModel: "gpt-5.5", Keys: piKeys("{endpoint}/v1", "openai-completions")},
	},
	Notice: "Pi now starts on the netbird provider. Run `netbird agent-network setup undo pi` to switch back.",
	CAEnv:  "NODE_EXTRA_CA_CERTS",
}
