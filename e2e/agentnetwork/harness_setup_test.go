//go:build e2e

package agentnetwork

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestHarnessSetupClaudeCode covers what `netbird agent-network setup
// claude-code` relies on, from a real agent:
//
//   - The daemon relays GetAgentNetworkInfo and the CLI writes the config.
//     Harness peers join with a setup key, so they have no owning user;
//     management answers them from their peer groups, so setup writes
//     settings.json into CLAUDE_CONFIG_DIR with the endpoint and model.
//   - The values setup renders for an Anthropic provider work through the
//     endpoint: base URL as-is, the apiKeyHelper's "-" as the only credential,
//     and the provider's model. This is the request Claude Code makes.
func TestHarnessSetupClaudeCode(t *testing.T) {
	ctx := context.Background()

	vllm, err := harness.StartVLLM(ctx, srv)
	require.NoError(t, err, "start mock upstream")
	t.Cleanup(func() { _ = vllm.Terminate(context.Background()) })

	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-harness-setup"})
	require.NoError(t, err, "create group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-harness-setup-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")

	prov, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        "e2e-harness-setup-anthropic",
		ProviderId:  "anthropic_api",
		UpstreamUrl: vllm.URL,
		ApiKey:      ptr("sk-harness-setup-e2e"),
		Enabled:     ptr(true),
		Models:      &[]api.AgentNetworkProviderModel{{Id: matrixAnthropicModel, InputPer1k: 0.003, OutputPer1k: 0.015}},
	})
	require.NoError(t, err, "create provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })

	pol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-harness-setup",
		Enabled:                ptr(true),
		SourceGroups:           []string{grp.Id},
		DestinationProviderIds: []string{prov.Id},
	})
	require.NoError(t, err, "create policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), pol.Id) })

	endpoint, proxyIP, cl, _ := connectClient(t, ctx, "harness-setup", sk.Key)

	t.Run("setup-key peer is set up", func(t *testing.T) {
		code, out, err := cl.Exec(ctx, "sh", "-c",
			"CLAUDE_CONFIG_DIR=/tmp/claude netbird agent-network setup claude-code; echo exit=$?; cat /tmp/claude/settings.json 2>&1; true")
		require.NoError(t, err, "exec setup in the client")
		require.Equal(t, 0, code, out)
		assert.Contains(t, out, "exit=0", "setup succeeds for a setup-key peer")
		assert.Contains(t, out, `"ANTHROPIC_BASE_URL"`, "settings.json points Claude Code at the endpoint")
		assert.Contains(t, out, `"`+matrixAnthropicModel+`"`, "settings.json carries the provider's model")
		assert.Contains(t, out, `"apiKeyHelper"`, "settings.json carries the placeholder key helper")
	})

	t.Run("rendered values reach the provider", func(t *testing.T) {
		body := `{"model":"` + matrixAnthropicModel + `","max_tokens":32,"messages":[{"role":"user","content":"Say hello in one word."}]}`
		code, resp := callUntil(t, func() (int, string, error) {
			return cl.PostJSON(ctx, endpoint, proxyIP, "/v1/messages", body, []string{
				"anthropic-version: 2023-06-01",
				// Claude Code sends the apiKeyHelper output as the API key.
				"x-api-key: -",
			})
		}, http.StatusOK)
		assert.Equal(t, http.StatusOK, code, "the placeholder key and base URL work through the endpoint: %s", resp)
	})
}
