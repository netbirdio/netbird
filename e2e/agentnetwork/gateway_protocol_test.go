//go:build e2e

package agentnetwork

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// Models each catalog surface is registered with in the matrix below. They
// differ per provider so the router's choice is unambiguous: a request that
// lands on the wrong provider record fails the surface assertion instead of
// passing by coincidence.
const (
	matrixAnthropicModel = "claude-sonnet-5"
	matrixBedrockModel   = "anthropic.claude-sonnet-5"
	// matrixBedrockPathModel is what a Bedrock SDK client puts in the URL: a
	// cross-region inference profile with a release date and version suffix.
	// The proxy must normalise it back to matrixBedrockModel to route and price.
	matrixBedrockPathModel = "us.anthropic.claude-sonnet-5-20250101-v1:0"
	// matrixVertexModel differs from the Anthropic record's model on purpose:
	// a shared id would leave two routes claiming it and make which one serves
	// /v1/messages depend on declaration order.
	matrixVertexModel   = "claude-haiku-4-5"
	matrixVertexProject = "e2e-project"
	matrixVertexRegion  = "us-east5"
)

// gatewayEnv is a connected client plus a set of provider records, all pointed
// at one mock upstream, so several wire shapes can be driven over a single
// tunnel.
type gatewayEnv struct {
	endpoint string
	proxyIP  string
	client   *harness.Client
	proxy    *harness.Proxy
	vllm     *harness.VLLM
	// providerIDs maps the catalog id to the created provider record id.
	providerIDs map[string]string
}

// provisionGatewayMatrix brings up one mock upstream and one provider record
// per catalog surface, all authorised for the same group by a single policy.
// Sharing one proxy and client keeps the wire-shape cases to one tunnel setup;
// each case still creates its own session id so its access-log row is findable.
func provisionGatewayMatrix(t *testing.T, ctx context.Context) gatewayEnv {
	t.Helper()

	vllm, err := harness.StartVLLM(ctx, srv)
	require.NoError(t, err, "start mock upstream")
	t.Cleanup(func() { _ = vllm.Terminate(context.Background()) })

	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-gw-matrix"})
	require.NoError(t, err, "create group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-gw-matrix-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")
	require.NotEmpty(t, sk.Key, "setup key plaintext")

	// The mock ignores auth, so a dummy credential satisfies each catalog
	// entry's auth template. Vertex is the exception: its api_key is a GCP
	// service-account keyfile the proxy mints an OAuth token from, and a dummy
	// one cannot mint. That is deliberate — the Vertex case below asserts on
	// routing, which happens before the token mint.
	dummyKey := "sk-gw-e2e"
	dummyKeyfile := "keyfile::" + "e2e-not-a-real-service-account-key"

	specs := []struct {
		name      string
		catalogID string
		apiKey    string
		models    []api.AgentNetworkProviderModel
	}{
		{
			name: "openai", catalogID: "openai_api", apiKey: dummyKey,
			models: []api.AgentNetworkProviderModel{{Id: harness.VLLMModel, InputPer1k: 0.001, OutputPer1k: 0.002}},
		},
		{
			name: "anthropic", catalogID: "anthropic_api", apiKey: dummyKey,
			models: []api.AgentNetworkProviderModel{{Id: matrixAnthropicModel, InputPer1k: 0.003, OutputPer1k: 0.015}},
		},
		{
			name: "bedrock", catalogID: "bedrock_api", apiKey: dummyKey,
			models: []api.AgentNetworkProviderModel{{Id: matrixBedrockModel, InputPer1k: 0.003, OutputPer1k: 0.015}},
		},
		{
			name: "vertex", catalogID: "vertex_ai_api", apiKey: dummyKeyfile,
			models: []api.AgentNetworkProviderModel{{Id: matrixVertexModel, InputPer1k: 0.001, OutputPer1k: 0.005}},
		},
	}

	providerIDs := make(map[string]string, len(specs))
	ids := make([]string, 0, len(specs))
	for _, spec := range specs {
		key := spec.apiKey
		models := spec.models
		prov, perr := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
			Name:        "e2e-gw-" + spec.name,
			ProviderId:  spec.catalogID,
			UpstreamUrl: vllm.URL,
			ApiKey:      &key,
			Enabled:     ptr(true),
			Models:      &models,
		})
		require.NoError(t, perr, "create %s provider", spec.name)
		id := prov.Id
		t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), id) })
		providerIDs[spec.catalogID] = id
		ids = append(ids, id)
	}

	// Uncapped token limit: never blocks the handful of tokens driven here, but
	// switches on usage metering so consumption and cost land in the row.
	enabled := true
	pol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-gw-matrix",
		Enabled:                &enabled,
		SourceGroups:           []string{grp.Id},
		DestinationProviderIds: ids,
		Limits: &api.AgentNetworkPolicyLimits{
			TokenLimit: api.AgentNetworkPolicyTokenLimit{
				Enabled:       true,
				GroupCap:      10_000_000,
				UserCap:       10_000_000,
				WindowSeconds: 60,
			},
		},
	})
	require.NoError(t, err, "create policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), pol.Id) })

	endpoint, proxyIP, cl, px := connectClient(t, ctx, "gw-matrix", sk.Key)
	return gatewayEnv{
		endpoint:    endpoint,
		proxyIP:     proxyIP,
		client:      cl,
		proxy:       px,
		vllm:        vllm,
		providerIDs: providerIDs,
	}
}

// connectClient starts a proxy and a tunnel client for the shared account and
// waits until the client can reach the proxy peer, returning the endpoint and
// the proxy's tunnel IP to pin requests to.
func connectClient(t *testing.T, ctx context.Context, name, setupKey string) (string, string, *harness.Client, *harness.Proxy) {
	t.Helper()

	settings, err := srv.GetSettings(ctx)
	require.NoError(t, err, "read settings")
	require.NotEmpty(t, settings.Endpoint, "endpoint must be assigned")

	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-"+name+"-proxy")
	require.NoError(t, err, "mint proxy token")
	px, err := harness.StartProxy(ctx, srv, proxyToken)
	require.NoError(t, err, "start proxy")
	t.Cleanup(func() { _ = px.Terminate(context.Background()) })

	cl, err := harness.StartClient(ctx, srv, setupKey)
	require.NoError(t, err, "start client")
	t.Cleanup(func() { _ = cl.Terminate(context.Background()) })

	require.NoError(t, cl.WaitConnected(ctx, 90*time.Second), "client must connect to management")
	// The probe resolves the endpoint and its first packet wakes the lazy proxy
	// peer, so WaitProxyPeer then observes it connected.
	proxyIP, err := cl.ResolveProxyIP(ctx, settings.Endpoint)
	require.NoError(t, err, "resolve endpoint to proxy IP")
	if err := cl.WaitProxyPeer(ctx, 180*time.Second); err != nil {
		t.Fatalf("client did not see the proxy peer: %v\n=== proxy logs ===\n%s", err, px.Logs(context.Background()))
	}
	return settings.Endpoint, proxyIP, cl, px
}

// callUntil retries an HTTP call through the tunnel until it returns one of the
// wanted statuses or the deadline passes, absorbing the DNS and tunnel jitter
// the first call through a fresh tunnel can hit. The last status and body are
// returned either way so the caller can assert with real detail.
func callUntil(t *testing.T, call func() (int, string, error), want ...int) (int, string) {
	t.Helper()
	wanted := make(map[int]struct{}, len(want))
	for _, w := range want {
		wanted[w] = struct{}{}
	}

	var code int
	var body string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		c, b, err := call()
		if err == nil {
			code, body = c, b
			if _, ok := wanted[code]; ok {
				return code, body
			}
		}
		time.Sleep(5 * time.Second)
	}
	return code, body
}

// TestGatewayProtocolProviderMatrix drives one request per wire shape over a
// single tunnel, with a provider record per catalog surface behind it. It is
// the regression net for the routing and parser-selection changes: each case
// asserts the surface the request was metered under and the token counts that
// surface's own usage block carries, so a request parsed by the wrong provider's
// parser meters zero and fails rather than passing on a coincidence.
func TestGatewayProtocolProviderMatrix(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	env := provisionGatewayMatrix(t, ctx)
	diag := func() string {
		return fmt.Sprintf("\n=== upstream logs ===\n%s\n=== proxy logs ===\n%s",
			env.vllm.Logs(context.Background()), env.proxy.Logs(context.Background()))
	}

	t.Run("openai chat completions", func(t *testing.T) {
		session := "e2e-gw-openai"
		code, body := callUntil(t, func() (int, string, error) {
			return env.client.Chat(ctx, env.endpoint, env.proxyIP, harness.WireChat, harness.VLLMModel, "ping", session)
		}, 200)
		require.Equal(t, 200, code, "openai chat must succeed; body: %s%s", body, diag())
		require.Contains(t, body, "chat.completion", "body must be an OpenAI completion; got: %s", body)

		row := findAccessLogBySession(t, ctx, session)
		require.NotNil(t, row.Provider)
		assert.Equal(t, "openai", *row.Provider, "the OpenAI chat path must meter under the openai surface")
		assert.Equal(t, int64(harness.VLLMChatInputTokens), row.InputTokens, "OpenAI usage block must be read")
		assert.Equal(t, int64(harness.VLLMChatOutputTokens), row.OutputTokens)
	})

	t.Run("anthropic messages", func(t *testing.T) {
		session := "e2e-gw-anthropic"
		code, body := callUntil(t, func() (int, string, error) {
			return env.client.Chat(ctx, env.endpoint, env.proxyIP, harness.WireMessages, matrixAnthropicModel, "ping", session)
		}, 200)
		require.Equal(t, 200, code, "anthropic messages must succeed; body: %s%s", body, diag())

		row := findAccessLogBySession(t, ctx, session)
		require.NotNil(t, row.Provider)
		assert.Equal(t, "anthropic", *row.Provider, "the /v1/messages path must meter under the anthropic surface")
		// These counts only appear if the Anthropic parser read the response:
		// its usage fields are named differently from the OpenAI block.
		assert.Equal(t, int64(harness.VLLMMessagesInputTokens), row.InputTokens,
			"Anthropic input_tokens must be read; zero here means the wrong parser ran")
		assert.Equal(t, int64(harness.VLLMMessagesOutputTokens), row.OutputTokens)
		assert.Positive(t, row.CachedInputTokens, "the Anthropic cache-read bucket must be recorded")
		assert.Positive(t, row.CostUsd, "a metered request must carry a cost")
		require.NotNil(t, row.ResolvedProviderId)
		assert.Equal(t, env.providerIDs["anthropic_api"], *row.ResolvedProviderId,
			"a vendor-tagged request must not cross to another provider's record")
	})

	t.Run("bedrock invoke normalises the path model", func(t *testing.T) {
		session := "e2e-gw-bedrock"
		code, body := callUntil(t, func() (int, string, error) {
			return env.client.Bedrock(ctx, env.endpoint, env.proxyIP, matrixBedrockPathModel, "ping", session)
		}, 200)
		require.Equal(t, 200, code, "bedrock invoke must succeed; body: %s%s", body, diag())

		row := findAccessLogBySession(t, ctx, session)
		require.NotNil(t, row.Provider)
		assert.Equal(t, "bedrock", *row.Provider, "a native Bedrock path must meter under the bedrock surface")
		require.NotNil(t, row.Model)
		assert.Equal(t, matrixBedrockModel, *row.Model,
			"the inference-profile prefix, release date and version suffix must be normalised away")
		assert.Equal(t, int64(harness.VLLMMessagesInputTokens), row.InputTokens)
	})

	t.Run("anthropic token counting", func(t *testing.T) {
		code, body := callUntil(t, func() (int, string, error) {
			return env.client.PostJSON(ctx, env.endpoint, env.proxyIP, "/v1/messages/count_tokens",
				fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"ping"}]}`, matrixAnthropicModel),
				[]string{"anthropic-version: 2023-06-01"})
		}, 200)
		assert.Equal(t, 200, code, "token counting must route rather than deny; body: %s%s", body, diag())
	})

	t.Run("bedrock token counting", func(t *testing.T) {
		code, body := callUntil(t, func() (int, string, error) {
			return env.client.PostJSON(ctx, env.endpoint, env.proxyIP,
				"/model/"+matrixBedrockPathModel+"/count-tokens",
				`{"input":{"converse":{"messages":[{"role":"user","content":[{"text":"ping"}]}]}}}`, nil)
		}, 200)
		assert.Equal(t, 200, code,
			"the Bedrock count-tokens action must route; denying it pushes counting onto the billable inference path; body: %s%s",
			body, diag())
	})

	t.Run("vertex token counting reaches its provider", func(t *testing.T) {
		// The dummy service-account key cannot mint an OAuth token, so the
		// request stops at the upstream credential. Both outcomes render as
		// 403, so the deny code is what distinguishes them: upstream_auth_failed
		// means the path resolved to the Vertex route and only the credential
		// failed, while model_not_routable would mean the method segment was
		// swallowed into the model id and no route ever claimed it.
		path := fmt.Sprintf("/v1/projects/%s/locations/%s/publishers/anthropic/models/%s/count-tokens:rawPredict",
			matrixVertexProject, matrixVertexRegion, matrixVertexModel)
		_, body := callUntil(t, func() (int, string, error) {
			return env.client.PostJSON(ctx, env.endpoint, env.proxyIP, path,
				`{"anthropic_version":"vertex-2023-10-16","messages":[{"role":"user","content":"ping"}]}`, nil)
		}, 403)
		assert.NotContains(t, body, "model_not_routable",
			"the count-tokens method segment must not be parsed as part of the model id; body: %s%s", body, diag())
		assert.Contains(t, body, "llm_policy.upstream_auth_failed",
			"the request must reach the Vertex route and fail only at the credential; body: %s%s", body, diag())
	})

	t.Run("connection warming probe", func(t *testing.T) {
		code, body := callUntil(t, func() (int, string, error) {
			return env.client.Get(ctx, env.endpoint, env.proxyIP, "/api/hello", nil)
		}, 200)
		assert.NotEqual(t, 403, code,
			"the warm-up probe carries no model and must not be refused as unroutable; body: %s%s", body, diag())
	})

	t.Run("unknown model denies in the caller's error shape", func(t *testing.T) {
		code, body := callUntil(t, func() (int, string, error) {
			return env.client.Chat(ctx, env.endpoint, env.proxyIP, harness.WireMessages,
				"claude-not-a-real-model-9", "ping", "e2e-gw-unknown")
		}, 403)
		require.Equal(t, 403, code, "a model no provider claims must still be refused; body: %s%s", body, diag())

		// The NetBird fields stay where they were for existing consumers.
		assert.Contains(t, body, "llm_policy.model_not_routable", "the deny code must be preserved")
		// And the vendor's own envelope rides alongside, so the client can show
		// the reason instead of an unexplained API error.
		assert.Contains(t, body, `"type":"error"`, "an Anthropic caller must get the Anthropic error envelope")
		assert.Contains(t, body, "permission_error", "403 must map to the vendor's permission error type")
	})
}

// TestModelDiscoveryWithModelAllowlist covers gateway model discovery on an
// account that restricts models, which is the configuration that broke: the
// listing carries no model, and the per-model allowlist fails closed on an
// undetermined one, so discovery denied for exactly the accounts using the
// feature. It also asserts the allowlist still refuses a model outside it, so
// the exemption cannot be read as a way around the gate.
func TestModelDiscoveryWithModelAllowlist(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	vllm, err := harness.StartVLLM(ctx, srv)
	require.NoError(t, err, "start mock upstream")
	t.Cleanup(func() { _ = vllm.Terminate(context.Background()) })

	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-gw-discovery"})
	require.NoError(t, err, "create group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-gw-discovery-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")
	require.NotEmpty(t, sk.Key, "setup key plaintext")

	// One provider enumerating a single model, while the upstream's own listing
	// advertises two. The proxy must serve the shorter list.
	dummyKey := "sk-discovery-e2e"
	prov, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        "e2e-gw-discovery",
		ProviderId:  "openai_api",
		UpstreamUrl: vllm.URL,
		ApiKey:      &dummyKey,
		Enabled:     ptr(true),
		Models: &[]api.AgentNetworkProviderModel{
			{Id: harness.VLLMModel, InputPer1k: 0.001, OutputPer1k: 0.002},
		},
	})
	require.NoError(t, err, "create provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })

	// The model allowlist is what makes this a regression test: without a
	// guardrail enabled, discovery was never gated in the first place.
	var gr api.AgentNetworkGuardrailRequest
	gr.Name = "e2e-gw-discovery-allowlist"
	gr.Checks.ModelAllowlist.Enabled = true
	gr.Checks.ModelAllowlist.Models = []string{harness.VLLMModel}
	guard, err := srv.CreateGuardrail(ctx, gr)
	require.NoError(t, err, "create guardrail")
	t.Cleanup(func() { _ = srv.DeleteGuardrail(context.Background(), guard.Id) })

	enabled := true
	pol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-gw-discovery",
		Enabled:                &enabled,
		SourceGroups:           []string{grp.Id},
		DestinationProviderIds: []string{prov.Id},
		GuardrailIds:           &[]string{guard.Id},
	})
	require.NoError(t, err, "create policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), pol.Id) })

	endpoint, proxyIP, cl, px := connectClient(t, ctx, "gw-discovery", sk.Key)
	diag := func() string {
		return fmt.Sprintf("\n=== upstream logs ===\n%s\n=== proxy logs ===\n%s",
			vllm.Logs(context.Background()), px.Logs(context.Background()))
	}

	t.Run("listing is served and bounded by policy", func(t *testing.T) {
		code, body := callUntil(t, func() (int, string, error) {
			return cl.Get(ctx, endpoint, proxyIP, "/v1/models?limit=1000", nil)
		}, 200)
		require.Equal(t, 200, code,
			"discovery must not be refused because the request carries no model; body: %s%s", body, diag())

		assert.Contains(t, body, harness.VLLMModel, "the authorised model must reach the picker")
		assert.NotContains(t, body, harness.VLLMUnlistedModel,
			"a model the policy does not authorise must not be offered; body: %s", body)
	})

	t.Run("allowlist still refuses a model outside it", func(t *testing.T) {
		code, body := callUntil(t, func() (int, string, error) {
			return cl.Chat(ctx, endpoint, proxyIP, harness.WireChat,
				harness.VLLMUnlistedModel, "ping", "e2e-gw-discovery-blocked")
		}, 403)
		require.Equal(t, 403, code,
			"exempting model-less endpoints must not exempt inference; body: %s%s", body, diag())
		assert.True(t,
			strings.Contains(body, "llm_policy.model_blocked") || strings.Contains(body, "llm_policy.model_not_routable"),
			"the refusal must name a model policy code; body: %s", body)
	})

	t.Run("allowlisted model still routes", func(t *testing.T) {
		code, body := callUntil(t, func() (int, string, error) {
			return cl.Chat(ctx, endpoint, proxyIP, harness.WireChat,
				harness.VLLMModel, "ping", "e2e-gw-discovery-allowed")
		}, 200)
		require.Equal(t, 200, code, "the allowlisted model must still be served; body: %s%s", body, diag())
	})
}
