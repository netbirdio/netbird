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

// pathRoutedGuardrailCase is one provider's self-contained scenario: its own
// provider, its own guardrail whose allowlist holds ONLY that provider's
// allowed model, and its own policy. Each case runs in isolation (its own
// proxy + client), so the guardrail the proxy enforces contains exactly this
// provider's model — never a mixed cross-provider list.
type pathRoutedGuardrailCase struct {
	name       string
	catalogID  string // agent-network catalog provider id
	wire       string // harness.WireVertex | harness.WireBedrock
	allowEntry string // the single model id put on the guardrail allowlist
	allowModel string // model id sent that MUST be served (200)
	blockModel string // model id sent that MUST be denied (403 model_blocked)
}

// TestGuardrailBlocksUnselectedModel_PathRouted is the end-to-end regression
// guard for the customer report that a model-allowlist guardrail attached to a
// policy has no effect for PATH-ROUTED providers — where the model travels in
// the URL, not the JSON body: Google Vertex (…/models/{model}:rawPredict) and
// AWS Bedrock (/model/{id}/invoke).
//
// Each provider is tested in isolation with a guardrail allowlisting a single
// model of its own: the allowed model (in the URL path) is served (200) and an
// unselected model (in the URL path) is denied 403 by the guardrail
// (llm_policy.model_blocked) before the upstream. The Vertex case mirrors the
// customer verbatim — allow Sonnet, and the unselected model is the exact
// claude-opus-4-6 they reported reaching the model unblocked. The Bedrock case
// sends a region-prefixed, versioned inference-profile id so URL-path model
// normalization is exercised too.
//
// The provider is catch-all (no models), so the router forwards any model and a
// 403 can only come from the guardrail, never model_not_routable. Only the
// upstream LLM is mocked (the vLLM nginx answers any path with 200); management
// synth/reconcile, the proxy middleware chain (URL-path model extraction,
// router, guardrail) and the tunnel are all real, and the guardrail denies
// before the upstream is dialed so the mock cannot influence the block. A
// static bearer api key is used so the router injects a static Authorization
// header instead of minting a GCP token — the only reason path-routed providers
// normally need live credentials — so the test runs with none and is always on.
func TestGuardrailBlocksUnselectedModel_PathRouted(t *testing.T) {
	cases := []pathRoutedGuardrailCase{
		{
			name:       "vertex",
			catalogID:  "vertex_ai_api",
			wire:       harness.WireVertex,
			allowEntry: "claude-sonnet-4-5",
			allowModel: "claude-sonnet-4-5",
			blockModel: "claude-opus-4-6", // the customer-reported model
		},
		{
			name:       "bedrock",
			catalogID:  "bedrock_api",
			wire:       harness.WireBedrock,
			allowEntry: "anthropic.claude-sonnet-4-5", // normalized catalog id
			allowModel: "us.anthropic.claude-sonnet-4-5-v1:0",
			blockModel: "us.anthropic.claude-opus-4-8-v1:0",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			runPathRoutedGuardrailCase(t, tc)
		})
	}
}

func runPathRoutedGuardrailCase(t *testing.T, tc pathRoutedGuardrailCase) {
	t.Helper()

	const (
		vertexProject = "e2e-project"
		vertexRegion  = "global"
	)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	vllm, err := harness.StartVLLM(ctx, srv)
	require.NoError(t, err, "start mock upstream")
	t.Cleanup(func() { _ = vllm.Terminate(context.Background()) })

	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-guardrail-" + tc.name})
	require.NoError(t, err, "create group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-guardrail-" + tc.name + "-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")
	require.NotEmpty(t, sk.Key, "setup key plaintext")

	// Catch-all provider (no models) so the router forwards any model; a static
	// bearer key means the router injects a static auth header instead of minting
	// a GCP token. Bootstraps the cluster if it isn't already.
	staticKey := "static-e2e-token"
	prov, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:             tc.name,
		ProviderId:       tc.catalogID,
		UpstreamUrl:      vllm.URL,
		ApiKey:           &staticKey,
		Enabled:          ptr(true),
		BootstrapCluster: ptr(harness.AgentNetworkCluster),
	})
	require.NoError(t, err, "create %s provider", tc.name)
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })

	// Guardrail allowlisting ONLY this provider's allowed model.
	var gr api.AgentNetworkGuardrailRequest
	gr.Name = "e2e-guardrail-" + tc.name
	gr.Checks.ModelAllowlist.Enabled = true
	gr.Checks.ModelAllowlist.Models = []string{tc.allowEntry}
	guard, err := srv.CreateGuardrail(ctx, gr)
	require.NoError(t, err, "create guardrail")
	t.Cleanup(func() { _ = srv.DeleteGuardrail(context.Background(), guard.Id) })

	enabled := true
	pol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-guardrail-" + tc.name,
		Enabled:                &enabled,
		SourceGroups:           []string{grp.Id},
		DestinationProviderIds: []string{prov.Id},
		GuardrailIds:           &[]string{guard.Id},
	})
	require.NoError(t, err, "create policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), pol.Id) })

	settings, err := srv.GetSettings(ctx)
	require.NoError(t, err, "read settings")
	require.NotEmpty(t, settings.Endpoint, "endpoint must be assigned")

	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-guardrail-"+tc.name+"-proxy")
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

	send := func(model string) (int, string) {
		var code int
		var body string
		var cerr error
		switch tc.wire {
		case harness.WireVertex:
			code, body, cerr = cl.Vertex(ctx, settings.Endpoint, proxyIP, vertexProject, vertexRegion, model, "Reply with exactly: pong", "")
		case harness.WireBedrock:
			code, body, cerr = cl.Bedrock(ctx, settings.Endpoint, proxyIP, model, "Reply with exactly: pong", "")
		default:
			t.Fatalf("unsupported wire %q", tc.wire)
		}
		require.NoError(t, cerr, "request must reach the proxy for %s", tc.name)
		return code, body
	}

	// Allowed model (in the URL path) is served. Retry to absorb tunnel/DNS
	// jitter on the first call over the freshly warmed tunnel.
	var code int
	var body string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		code, body = send(tc.allowModel)
		if code == 200 {
			break
		}
		time.Sleep(5 * time.Second)
	}
	assert.Equal(t, 200, code,
		"allowed %s model (URL path) must be served; body: %s\n=== proxy logs ===\n%s", tc.name, body, px.Logs(context.Background()))

	// Unselected model (in the URL path) must be blocked by the guardrail.
	code, body = send(tc.blockModel)
	assert.Equal(t, 403, code,
		"unselected %s model (URL path) must be denied, not served; body: %s\n=== proxy logs ===\n%s", tc.name, body, px.Logs(context.Background()))
	assert.Contains(t, body, "llm_policy.model_blocked",
		"%s denial must come from the guardrail allowlist, not routing; body: %s", tc.name, body)
}
