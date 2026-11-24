//go:build e2e

package agentnetwork

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
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
//   - The values in that settings.json work through the endpoint: its base
//     URL, the output of its apiKeyHelper as the only credential, and its
//     model. This is the request Claude Code makes.
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

	// What setup wrote, as Claude Code reads it.
	var written struct {
		APIKeyHelper string            `json:"apiKeyHelper"`
		Model        string            `json:"model"`
		Env          map[string]string `json:"env"`
	}
	t.Run("setup-key peer is set up", func(t *testing.T) {
		code, out, err := cl.Exec(ctx, "sh", "-c", "CLAUDE_CONFIG_DIR=/tmp/claude netbird agent-network setup claude-code")
		require.NoError(t, err, "exec setup in the client")
		require.Equal(t, 0, code, "setup succeeds for a setup-key peer: %s", out)

		code, out, err = cl.Exec(ctx, "cat", "/tmp/claude/settings.json")
		require.NoError(t, err, "exec cat in the client")
		require.Equal(t, 0, code, "settings.json is written: %s", out)
		require.NoError(t, json.Unmarshal([]byte(out), &written), "settings.json is JSON: %s", out)
		assert.Equal(t, matrixAnthropicModel, written.Model, "settings.json carries the provider's model")
		assert.NotEmpty(t, written.APIKeyHelper, "settings.json carries the placeholder key helper")
	})

	t.Run("rendered values reach the provider", func(t *testing.T) {
		require.NotNil(t, written.Env, "setup must have written settings.json")
		base, err := url.Parse(written.Env["ANTHROPIC_BASE_URL"])
		require.NoError(t, err, "parse the rendered base URL")
		assert.Equal(t, "https", base.Scheme, "the base URL is HTTPS")
		assert.Equal(t, endpoint, base.Host, "the base URL points at the endpoint")

		// Claude Code runs the apiKeyHelper and sends its output as the key.
		code, key, err := cl.Exec(ctx, "sh", "-c", written.APIKeyHelper)
		require.NoError(t, err, "exec the key helper in the client")
		require.Equal(t, 0, code, "the key helper runs: %s", key)

		body := `{"model":"` + written.Model + `","max_tokens":32,"messages":[{"role":"user","content":"Say hello in one word."}]}`
		code, resp := callUntil(t, func() (int, string, error) {
			return cl.PostJSON(ctx, base.Host, proxyIP, strings.TrimRight(base.Path, "/")+"/v1/messages", body, []string{
				"anthropic-version: 2023-06-01",
				"x-api-key: " + strings.TrimSpace(key),
			})
		}, http.StatusOK)
		assert.Equal(t, http.StatusOK, code, "the rendered base URL, key and model work through the endpoint: %s", resp)
	})
}
