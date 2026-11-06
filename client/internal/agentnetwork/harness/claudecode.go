package harness

// The proxy authorizes by the peer's tunnel IP, so Claude Code needs no real
// credential. apiKeyHelper hands it a placeholder, which also keeps a saved
// claude.ai login out of the requests while the settings are in place.
const claudeKeyHelper = "echo '-'"

// claudeCode mirrors the dashboard's Claude Code snippets
// (dashboard src/modules/agent-network/AgentConnectTabs.tsx).
var claudeCode = &Definition{
	ID:             "claude-code",
	Name:           "Claude Code",
	CheckedVersion: "2.1.318",
	Files: []File{{
		DirEnv: "CLAUDE_CONFIG_DIR",
		Dir:    ".claude",
		Name:   "settings.json",
		Format: FormatJSON,
	}},
	Variants: map[string]Variant{
		"anthropic": {Keys: []Key{
			{Path: []string{"apiKeyHelper"}, Value: claudeKeyHelper},
			{Path: []string{"model"}, Value: "{model}"},
			{Path: []string{"env", "ANTHROPIC_BASE_URL"}, Value: "{endpoint}"},
		}},
		"bedrock_api": {Keys: []Key{
			{Path: []string{"env", "ANTHROPIC_BEDROCK_BASE_URL"}, Value: "{endpoint}/bedrock"},
			{Path: []string{"env", "CLAUDE_CODE_USE_BEDROCK"}, Value: "1"},
			{Path: []string{"env", "ANTHROPIC_MODEL"}, Value: "{model}"},
			{Path: []string{"env", "CLAUDE_CODE_SKIP_BEDROCK_AUTH"}, Value: "1"},
		}},
		"vertex_ai_api": {Keys: []Key{
			{Path: []string{"env", "CLOUD_ML_REGION"}, Value: "global"},
			{Path: []string{"env", "ANTHROPIC_VERTEX_PROJECT_ID"}, Value: "{vertex_project}"},
			{Path: []string{"env", "CLAUDE_CODE_USE_VERTEX"}, Value: "1"},
			{Path: []string{"env", "CLAUDE_CODE_SKIP_VERTEX_AUTH"}, Value: "1"},
			{Path: []string{"env", "ANTHROPIC_MODEL"}, Value: "{model}"},
			{Path: []string{"env", "ANTHROPIC_VERTEX_BASE_URL"}, Value: "{endpoint}/v1"},
		}},
		// Moonshot serves the Anthropic Messages API under /anthropic. Every
		// model slot is pinned to the Kimi model so no Claude model name
		// reaches it, and tool search is off because Moonshot rejects its
		// tool_reference blocks.
		"kimi_api": {
			DefaultModel: "kimi-k3",
			Keys: []Key{
				{Path: []string{"apiKeyHelper"}, Value: claudeKeyHelper},
				{Path: []string{"env", "ANTHROPIC_BASE_URL"}, Value: "{endpoint}/anthropic"},
				{Path: []string{"env", "ANTHROPIC_MODEL"}, Value: "{model}"},
				{Path: []string{"env", "ANTHROPIC_DEFAULT_OPUS_MODEL"}, Value: "{model}"},
				{Path: []string{"env", "ANTHROPIC_DEFAULT_SONNET_MODEL"}, Value: "{model}"},
				{Path: []string{"env", "ANTHROPIC_DEFAULT_HAIKU_MODEL"}, Value: "{model}"},
				{Path: []string{"env", "CLAUDE_CODE_SUBAGENT_MODEL"}, Value: "{model}"},
				{Path: []string{"env", "ENABLE_TOOL_SEARCH"}, Value: "false"},
			},
		},
	},
	CAEnv: "NODE_EXTRA_CA_CERTS",
	Notice: "While these settings are in place, Claude Code sends its requests to Agent Networks " +
		"instead of your claude.ai account. Your claude.ai login stays saved; " +
		"run `netbird agent-network setup undo claude-code` to switch back.",
}
