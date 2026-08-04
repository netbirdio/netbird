package cmd

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/proto"
)

func anTestSetup(providers ...*proto.AgentNetworkProvider) *proto.GetAgentNetworkSetupResponse {
	return &proto.GetAgentNetworkSetupResponse{
		Configured: true,
		Endpoint:   "https://calm-otter.proxy.example.com",
		Providers:  providers,
	}
}

func TestBuildAgentNetworkEnv_AnthropicSingleModel(t *testing.T) {
	setup := anTestSetup(&proto.AgentNetworkProvider{
		Name: "Anthropic prod", CatalogId: "anthropic_api", ApiFlavor: "anthropic",
		Models: []string{"claude-sonnet-4-5"},
	})

	lines, err := buildAgentNetworkEnv(setup, "", "")
	require.NoError(t, err)
	assert.Equal(t, []string{
		"export ANTHROPIC_BASE_URL='https://calm-otter.proxy.example.com'",
		"export ANTHROPIC_AUTH_TOKEN='netbird'",
		"export ANTHROPIC_MODEL='claude-sonnet-4-5'",
	}, lines)
}

func TestBuildAgentNetworkEnv_MultipleModelsBecomeComments(t *testing.T) {
	setup := anTestSetup(&proto.AgentNetworkProvider{
		Name: "Anthropic prod", CatalogId: "anthropic_api", ApiFlavor: "anthropic",
		Models: []string{"claude-sonnet-4-5", "claude-haiku-4-5"},
	})

	lines, err := buildAgentNetworkEnv(setup, "", "")
	require.NoError(t, err)
	assert.Contains(t, lines, "export ANTHROPIC_BASE_URL='https://calm-otter.proxy.example.com'")
	assert.NotContains(t, strings.Join(lines, "\n"), "ANTHROPIC_MODEL=", "no model is ever guessed")
	assert.Contains(t, strings.Join(lines, "\n"), "# Multiple models are allowed")
}

func TestBuildAgentNetworkEnv_ModelFlagValidated(t *testing.T) {
	setup := anTestSetup(&proto.AgentNetworkProvider{
		Name: "Anthropic prod", CatalogId: "anthropic_api", ApiFlavor: "anthropic",
		Models: []string{"claude-sonnet-4-5", "claude-haiku-4-5"},
	})

	lines, err := buildAgentNetworkEnv(setup, "", "Claude-Haiku-4-5")
	require.NoError(t, err, "model match is case-insensitive")
	assert.Contains(t, lines, "export ANTHROPIC_MODEL='Claude-Haiku-4-5'")

	_, err = buildAgentNetworkEnv(setup, "", "gpt-4o")
	require.Error(t, err, "a model outside the allowlist is rejected")
}

func TestBuildAgentNetworkEnv_BedrockFlavor(t *testing.T) {
	setup := anTestSetup(&proto.AgentNetworkProvider{
		Name: "Bedrock prod", CatalogId: "bedrock_api", ApiFlavor: "",
		Models: []string{"anthropic.claude-sonnet-4-5"},
	})

	lines, err := buildAgentNetworkEnv(setup, "", "")
	require.NoError(t, err)
	assert.Equal(t, []string{
		"export CLAUDE_CODE_USE_BEDROCK='1'",
		"export ANTHROPIC_BEDROCK_BASE_URL='https://calm-otter.proxy.example.com'",
		"export CLAUDE_CODE_SKIP_BEDROCK_AUTH='1'",
		"export ANTHROPIC_MODEL='anthropic.claude-sonnet-4-5'",
	}, lines)
}

func TestBuildAgentNetworkEnv_VertexFlavorNotesProjectAndRegion(t *testing.T) {
	setup := anTestSetup(&proto.AgentNetworkProvider{
		Name: "Vertex prod", CatalogId: "vertex_ai_api", ApiFlavor: "",
		Models: []string{"claude-sonnet-4-5"},
	})

	lines, err := buildAgentNetworkEnv(setup, "", "")
	require.NoError(t, err)
	joined := strings.Join(lines, "\n")
	assert.Contains(t, lines, "export CLAUDE_CODE_USE_VERTEX='1'")
	assert.Contains(t, lines, "export ANTHROPIC_VERTEX_BASE_URL='https://calm-otter.proxy.example.com'")
	assert.Contains(t, lines, "export CLAUDE_CODE_SKIP_VERTEX_AUTH='1'")
	assert.Contains(t, lines, "export ANTHROPIC_MODEL='claude-sonnet-4-5'")
	assert.Contains(t, joined, "ANTHROPIC_VERTEX_PROJECT_ID", "project id must be called out as admin-supplied")
	assert.Contains(t, joined, "CLOUD_ML_REGION", "region must be called out as admin-supplied")
}

func TestBuildAgentNetworkEnv_OpenAIFlavor(t *testing.T) {
	setup := anTestSetup(&proto.AgentNetworkProvider{
		Name: "OpenAI prod", CatalogId: "openai_api", ApiFlavor: "openai",
		Models: []string{"gpt-5.4"},
	})

	lines, err := buildAgentNetworkEnv(setup, "", "")
	require.NoError(t, err)
	assert.Contains(t, lines, "export OPENAI_BASE_URL='https://calm-otter.proxy.example.com'")
	assert.Contains(t, lines, "export OPENAI_API_KEY='netbird'")
	assert.NotContains(t, strings.Join(lines, "\n"), "ANTHROPIC_", "openai flavor must not emit anthropic variables")
}

func TestBuildAgentNetworkEnv_MultipleProvidersRequireFlag(t *testing.T) {
	anthropic := &proto.AgentNetworkProvider{Name: "Anthropic prod", CatalogId: "anthropic_api", ApiFlavor: "anthropic", Models: []string{"claude-sonnet-4-5"}}
	bedrock := &proto.AgentNetworkProvider{Name: "Bedrock prod", CatalogId: "bedrock_api", Models: []string{"anthropic.claude-sonnet-4-5"}}
	setup := anTestSetup(anthropic, bedrock)

	lines, err := buildAgentNetworkEnv(setup, "", "")
	require.NoError(t, err)
	joined := strings.Join(lines, "\n")
	assert.NotContains(t, joined, "export ", "ambiguous provider choice must export nothing")
	assert.Contains(t, joined, "--provider")
	assert.Contains(t, joined, "Bedrock prod")

	// Selection by operator label, case-insensitive.
	lines, err = buildAgentNetworkEnv(setup, "bedrock prod", "")
	require.NoError(t, err)
	assert.Contains(t, lines, "export CLAUDE_CODE_USE_BEDROCK='1'")

	// Selection by catalog id.
	lines, err = buildAgentNetworkEnv(setup, "anthropic_api", "")
	require.NoError(t, err)
	assert.Contains(t, lines, "export ANTHROPIC_AUTH_TOKEN='netbird'")

	// Unknown provider is an error naming the available ones.
	_, err = buildAgentNetworkEnv(setup, "vertex", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Anthropic prod")
}

func TestBuildAgentNetworkEnv_AllModelsAllowed(t *testing.T) {
	setup := anTestSetup(&proto.AgentNetworkProvider{
		Name: "Anthropic prod", CatalogId: "anthropic_api", ApiFlavor: "anthropic",
		AllModelsAllowed: true, Models: []string{"claude-sonnet-4-5"},
	})

	// A courtesy-listed single model is still ambiguous when everything is allowed.
	lines, err := buildAgentNetworkEnv(setup, "", "")
	require.NoError(t, err)
	assert.NotContains(t, strings.Join(lines, "\n"), "ANTHROPIC_MODEL=")

	// --model passes without allowlist validation.
	lines, err = buildAgentNetworkEnv(setup, "", "claude-opus-4-8")
	require.NoError(t, err)
	assert.Contains(t, lines, "export ANTHROPIC_MODEL='claude-opus-4-8'")
}

func TestBuildAgentNetworkEnv_UnknownFlavorFallsBackToComments(t *testing.T) {
	setup := anTestSetup(&proto.AgentNetworkProvider{
		Name: "Kimi", CatalogId: "kimi_api", ApiFlavor: "",
		Models: []string{"kimi-k3"},
	})

	lines, err := buildAgentNetworkEnv(setup, "", "")
	require.NoError(t, err)
	joined := strings.Join(lines, "\n")
	assert.NotContains(t, joined, "export ", "unknown API shape must not guess variables")
	assert.Contains(t, joined, "https://calm-otter.proxy.example.com")
}
