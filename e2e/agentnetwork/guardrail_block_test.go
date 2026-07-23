//go:build e2e

package agentnetwork

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestGuardrailBlocksUnselectedModel_PathRouted is the end-to-end regression
// guard for the customer report that a model-allowlist guardrail attached to a
// policy "has no effect" for PATH-ROUTED providers — where the model travels in
// the URL, not the JSON body (Google Vertex `…/models/{model}:rawPredict`, AWS
// Bedrock `/model/{id}/invoke`). This is the shape the customer actually hits.
//
// Through the real management API it creates a Vertex and a Bedrock provider
// (both catch-all, so the router forwards any model — a 403 can only come from
// the guardrail, never model_not_routable) and one guardrail whose allowlist
// selects a single model per provider, attached to the policy. Over the tunnel,
// for each provider:
//
//   - the SELECTED model (in the URL path) is served (200), and
//   - an UNSELECTED model (in the URL path) is denied 403 by the guardrail
//     (llm_policy.model_blocked) before it reaches the upstream.
//
// Only the upstream LLM is mocked (the vLLM nginx answers any path with 200);
// management synth/reconcile, the proxy middleware chain (URL-path model
// extraction in llm_request_parser, llm_router, llm_guardrail), and the tunnel
// are all real. The guardrail denies before the upstream is dialed, so the mock
// cannot influence the block. Providers use a static bearer api key (not
// "keyfile::…") so the router injects a static Authorization header instead of
// minting a GCP OAuth token — that is the only reason path-routed providers
// normally need live credentials, so this test runs with none and is always on.
//
// If the guardrail were inert for path-routed requests (its middleware dropped
// by the proxy, the allowlist not synthesized, or the URL-path model not
// extracted so the allowlist can't match), the unselected model would reach the
// mock and return 200 — the fail-open this test catches.
func TestGuardrailBlocksUnselectedModel_PathRouted(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	const (
		vertexProject = "e2e-project"
		vertexRegion  = "global"

		// Vertex catalog ids travel bare in the rawPredict path.
		vertexSelected   = "claude-sonnet-4-5"
		vertexUnselected = "claude-opus-4-6"

		// Bedrock request ids travel as region-prefixed, versioned
		// inference-profile ids; the parser normalizes them to the catalog key
		// the allowlist holds — so this also exercises Bedrock normalization.
		bedrockSelectedPath    = "us.anthropic.claude-sonnet-4-5-v1:0"
		bedrockSelectedCatalog = "anthropic.claude-sonnet-4-5"
		bedrockUnselectedPath  = "us.anthropic.claude-opus-4-8-v1:0"
	)

	vllm, err := harness.StartVLLM(ctx, srv)
	require.NoError(t, err, "start mock upstream")
	t.Cleanup(func() { _ = vllm.Terminate(context.Background()) })

	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-guardrail-path"})
	require.NoError(t, err, "create group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-guardrail-path-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")
	require.NotEmpty(t, sk.Key, "setup key plaintext")

	// Static bearer (not "keyfile::…") so the router injects a static auth header
	// instead of minting a GCP token. Both providers are catch-all (no Models)
	// and point at the mock upstream. Create both up front, enabled, before the
	// proxy starts (provider changes after connect don't reconcile to the proxy).
	staticKey := "static-e2e-token"

	vertexProv, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:             "vertex",
		ProviderId:       "vertex_ai_api",
		UpstreamUrl:      vllm.URL,
		ApiKey:           &staticKey,
		Enabled:          ptr(true),
		BootstrapCluster: ptr(harness.AgentNetworkCluster),
	})
	require.NoError(t, err, "create vertex provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), vertexProv.Id) })

	bedrockProv, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        "bedrock",
		ProviderId:  "bedrock_api",
		UpstreamUrl: vllm.URL,
		ApiKey:      &staticKey,
		Enabled:     ptr(true),
	})
	require.NoError(t, err, "create bedrock provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), bedrockProv.Id) })

	// One guardrail allowlisting exactly the selected model per provider.
	var gr api.AgentNetworkGuardrailRequest
	gr.Name = "e2e-guardrail-path"
	gr.Checks.ModelAllowlist.Enabled = true
	gr.Checks.ModelAllowlist.Models = []string{vertexSelected, bedrockSelectedCatalog}
	guard, err := srv.CreateGuardrail(ctx, gr)
	require.NoError(t, err, "create guardrail")
	t.Cleanup(func() { _ = srv.DeleteGuardrail(context.Background(), guard.Id) })

	enabled := true
	pol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-guardrail-path",
		Enabled:                &enabled,
		SourceGroups:           []string{grp.Id},
		DestinationProviderIds: []string{vertexProv.Id, bedrockProv.Id},
		GuardrailIds:           &[]string{guard.Id},
	})
	require.NoError(t, err, "create policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), pol.Id) })

	settings, err := srv.GetSettings(ctx)
	require.NoError(t, err, "read settings")
	require.NotEmpty(t, settings.Endpoint, "endpoint must be assigned")

	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-guardrail-path-proxy")
	require.NoError(t, err, "mint proxy token")
	px, err := harness.StartProxy(ctx, srv, proxyToken)
	require.NoError(t, err, "start proxy")
	t.Cleanup(func() { _ = px.Terminate(context.Background()) })

	cl, err := harness.StartClient(ctx, srv, sk.Key)
	require.NoError(t, err, "start client")
	t.Cleanup(func() { _ = cl.Terminate(context.Background()) })

	require.NoError(t, cl.WaitConnected(ctx, 90*time.Second), "client must connect to management")
	// Probe first: the GET resolves the endpoint and its first packet wakes the
	// lazy proxy peer, so WaitProxyPeer then observes it connected.
	proxyIP, err := cl.ResolveProxyIP(ctx, settings.Endpoint)
	require.NoError(t, err, "resolve endpoint to proxy IP")
	if err := cl.WaitProxyPeer(ctx, 180*time.Second); err != nil {
		t.Fatalf("client did not see the proxy peer: %v\n=== proxy logs ===\n%s", err, px.Logs(context.Background()))
	}

	// vertexSend / bedrockSend drive one path-routed request and return status+body.
	vertexSend := func(model string) (int, string) {
		code, body, cerr := cl.Vertex(ctx, settings.Endpoint, proxyIP, vertexProject, vertexRegion, model, "Reply with exactly: pong", "")
		require.NoError(t, cerr, "vertex request must reach the proxy")
		return code, body
	}
	bedrockSend := func(model string) (int, string) {
		code, body, cerr := cl.Bedrock(ctx, settings.Endpoint, proxyIP, model, "Reply with exactly: pong", "")
		require.NoError(t, cerr, "bedrock request must reach the proxy")
		return code, body
	}

	t.Run("vertex", func(t *testing.T) {
		// Selected model (in the URL path) is served. Retry to absorb tunnel/DNS
		// jitter on the first call over the freshly warmed tunnel.
		var code int
		var body string
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			code, body = vertexSend(vertexSelected)
			if code == 200 {
				break
			}
			time.Sleep(5 * time.Second)
		}
		assert.Equal(t, 200, code,
			"selected Vertex model (URL path) must be served; body: %s\n=== proxy logs ===\n%s", body, px.Logs(context.Background()))

		// Unselected model (in the URL path) must be blocked by the guardrail.
		code, body = vertexSend(vertexUnselected)
		assert.Equal(t, 403, code,
			"unselected Vertex model (URL path) must be denied, not served; body: %s\n=== proxy logs ===\n%s", body, px.Logs(context.Background()))
		assert.Contains(t, body, "llm_policy.model_blocked",
			"Vertex denial must come from the guardrail allowlist, not routing; body: %s", body)
	})

	t.Run("bedrock", func(t *testing.T) {
		var code int
		var body string
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			code, body = bedrockSend(bedrockSelectedPath)
			if code == 200 {
				break
			}
			time.Sleep(5 * time.Second)
		}
		assert.Equal(t, 200, code,
			"selected Bedrock model (URL path, normalized) must be served; body: %s\n=== proxy logs ===\n%s", body, px.Logs(context.Background()))

		code, body = bedrockSend(bedrockUnselectedPath)
		assert.Equal(t, 403, code,
			"unselected Bedrock model (URL path) must be denied, not served; body: %s\n=== proxy logs ===\n%s", body, px.Logs(context.Background()))
		assert.Contains(t, body, "llm_policy.model_blocked",
			"Bedrock denial must come from the guardrail allowlist, not routing; body: %s", body)
	})
}
