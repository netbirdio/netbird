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

// pergroupCase describes one provider surface for the per-group allowlist matrix.
// selectedReq/otherReq are the model identifiers as they travel in the request
// (URL path for Bedrock/Vertex, body "model" for chat/messages). selectedAllow/
// otherAllow are the (normalized) forms the guardrail allowlist holds — for
// Bedrock these differ from the request form so path normalization is exercised.
type pergroupCase struct {
	name          string
	catalogID     string
	wire          string // "chat", "messages", "vertex", "bedrock"
	models        *[]api.AgentNetworkProviderModel
	selectedReq   string
	selectedAllow string
	otherReq      string
	otherAllow    string

	providerID string // filled during setup
}

// TestGuardrailPerGroupAllowlist_AllProviders proves the per-policy/group model
// allowlist end to end across every always-on provider surface, including the
// path-routed ones (Vertex, Bedrock) where the model travels in the URL.
//
// For each provider two policies target it: grpMain (the client) is allowed only
// selectedReq; grpOther (which the client is NOT in) is allowed only otherReq.
// The client must get selectedReq served (200) and otherReq denied (403,
// llm_policy.model_blocked) — the cross-group no-leak property. The deny is the
// authoritative per-policy/group decision from management (the proxy per-provider
// backstop carries the union of both models), so this also confirms management
// receives the correct normalized model for path-routed providers.
func TestGuardrailPerGroupAllowlist_AllProviders(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	const (
		vertexProject = "e2e-project"
		vertexRegion  = "global"
	)

	priced := func(ids ...string) *[]api.AgentNetworkProviderModel {
		out := make([]api.AgentNetworkProviderModel, 0, len(ids))
		for _, id := range ids {
			out = append(out, api.AgentNetworkProviderModel{Id: id, InputPer1k: 0.001, OutputPer1k: 0.001})
		}
		return &out
	}

	cases := []*pergroupCase{
		{
			name: "openai", catalogID: "openai_api", wire: harness.WireChat,
			models:      priced("oai-model-a", "oai-model-b"),
			selectedReq: "oai-model-a", selectedAllow: "oai-model-a",
			otherReq: "oai-model-b", otherAllow: "oai-model-b",
		},
		{
			name: "anthropic", catalogID: "anthropic_api", wire: harness.WireMessages,
			models:      priced("ant-model-a", "ant-model-b"),
			selectedReq: "ant-model-a", selectedAllow: "ant-model-a",
			otherReq: "ant-model-b", otherAllow: "ant-model-b",
		},
		{
			// Vertex catalog ids travel bare in the rawPredict path.
			name: "vertex", catalogID: "vertex_ai_api", wire: "vertex",
			selectedReq: "claude-sonnet-4-5", selectedAllow: "claude-sonnet-4-5",
			otherReq: "claude-opus-4-6", otherAllow: "claude-opus-4-6",
		},
		{
			// Bedrock request ids are region-prefixed/versioned; the parser
			// normalizes them to the catalog key the allowlist holds.
			name: "bedrock", catalogID: "bedrock_api", wire: "bedrock",
			selectedReq: "us.anthropic.claude-sonnet-4-5-v1:0", selectedAllow: "anthropic.claude-sonnet-4-5",
			otherReq: "us.anthropic.claude-opus-4-8-v1:0", otherAllow: "anthropic.claude-opus-4-8",
		},
	}

	vllm, err := harness.StartVLLM(ctx, srv)
	require.NoError(t, err, "start mock upstream")
	t.Cleanup(func() { _ = vllm.Terminate(context.Background()) })

	grpMain, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-pergroup-main"})
	require.NoError(t, err, "create main group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grpMain.Id) })

	grpOther, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-pergroup-other"})
	require.NoError(t, err, "create other group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grpOther.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-pergroup-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grpMain.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")
	require.NotEmpty(t, sk.Key, "setup key plaintext")

	staticKey := "static-e2e-token"
	enabled := true

	for _, c := range cases {
		req := api.AgentNetworkProviderRequest{
			Name:        "e2e-pergroup-" + c.name,
			ProviderId:  c.catalogID,
			UpstreamUrl: vllm.URL,
			ApiKey:      &staticKey,
			Enabled:     ptr(true),
			Models:      c.models,
		}
		prov, perr := srv.CreateProvider(ctx, req)
		require.NoError(t, perr, "create provider %s", c.name)
		c.providerID = prov.Id
		t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })

		gSel := mkAllowGuardrail(t, ctx, "e2e-pergroup-"+c.name+"-sel", c.selectedAllow)
		gOth := mkAllowGuardrail(t, ctx, "e2e-pergroup-"+c.name+"-oth", c.otherAllow)

		polMain, merr := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
			Name:                   "e2e-pergroup-" + c.name + "-main",
			Enabled:                &enabled,
			SourceGroups:           []string{grpMain.Id},
			DestinationProviderIds: []string{prov.Id},
			GuardrailIds:           &[]string{gSel.Id},
		})
		require.NoError(t, merr, "create main policy %s", c.name)
		t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), polMain.Id) })

		polOther, oerr := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
			Name:                   "e2e-pergroup-" + c.name + "-other",
			Enabled:                &enabled,
			SourceGroups:           []string{grpOther.Id},
			DestinationProviderIds: []string{prov.Id},
			GuardrailIds:           &[]string{gOth.Id},
		})
		require.NoError(t, oerr, "create other policy %s", c.name)
		t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), polOther.Id) })
	}

	settings, err := srv.GetSettings(ctx)
	require.NoError(t, err, "read settings")
	require.NotEmpty(t, settings.Endpoint, "endpoint must be assigned")

	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-pergroup-proxy")
	require.NoError(t, err, "mint proxy token")
	px, err := harness.StartProxy(ctx, srv, proxyToken)
	require.NoError(t, err, "start proxy")
	t.Cleanup(func() { _ = px.Terminate(context.Background()) })

	cl, err := harness.StartClient(ctx, srv, sk.Key)
	require.NoError(t, err, "start client")
	t.Cleanup(func() { _ = cl.Terminate(context.Background()) })

	require.NoError(t, cl.WaitConnected(ctx, 90*time.Second), "client must connect to management")
	proxyIP, err := cl.ResolveProxyIP(ctx, settings.Endpoint)
	require.NoError(t, err, "resolve endpoint to proxy IP")
	if err := cl.WaitProxyPeer(ctx, 180*time.Second); err != nil {
		t.Fatalf("client did not see the proxy peer: %v\n=== proxy logs ===\n%s", err, px.Logs(context.Background()))
	}

	send := func(c *pergroupCase, model string) (int, string) {
		var code int
		var body string
		var cerr error
		switch c.wire {
		case "vertex":
			code, body, cerr = cl.Vertex(ctx, settings.Endpoint, proxyIP, vertexProject, vertexRegion, model, "Reply with exactly: pong", "")
		case "bedrock":
			code, body, cerr = cl.Bedrock(ctx, settings.Endpoint, proxyIP, model, "Reply with exactly: pong", "")
		default:
			code, body, cerr = cl.Chat(ctx, settings.Endpoint, proxyIP, c.wire, model, "Reply with exactly: pong", "")
		}
		require.NoError(t, cerr, "request must reach the proxy for %s", c.name)
		return code, body
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// grpMain's own model is served. Retry to absorb tunnel/DNS jitter on
			// the first call over the freshly warmed tunnel.
			var code int
			var body string
			deadline := time.Now().Add(90 * time.Second)
			for time.Now().Before(deadline) {
				code, body = send(c, c.selectedReq)
				if code == 200 {
					break
				}
				time.Sleep(5 * time.Second)
			}
			assert.Equal(t, 200, code,
				"%s: grpMain's allowlisted model must be served; body: %s\n=== proxy logs ===\n%s", c.name, body, px.Logs(context.Background()))

			// grpOther's model must NOT leak to the grpMain client.
			code, body = send(c, c.otherReq)
			assert.Equal(t, 403, code,
				"%s: another group's allowlisted model must be denied for this caller; body: %s\n=== proxy logs ===\n%s", c.name, body, px.Logs(context.Background()))
			assert.Contains(t, body, "llm_policy.model_blocked",
				"%s: denial must be a model-allowlist decision, not routing; body: %s", c.name, body)
		})
	}
}

// TestGuardrailMultiGroupUser proves the per-policy/group decision for a caller
// that belongs to MULTIPLE groups at once. Two scenarios, one shared stack:
//
//   - union across the user's groups: the client is in gUX and gUY, each with
//     its own policy+guardrail on provider P1 (gUX->union-a, gUY->union-b). The
//     client may use BOTH models (the union of its groups' allowlists) while a
//     third, un-allowlisted model is denied.
//   - an un-guardrailed group lifts the restriction: the client is in gMP and
//     gMQ on provider P2, where gMP restricts to mix-a but gMQ's policy carries
//     NO guardrail. Because one applicable policy is unrestricted, the client may
//     use a model on no allowlist (mix-z) as well as mix-a.
func TestGuardrailMultiGroupUser(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	const (
		unionA = "mg-union-a"
		unionB = "mg-union-b"
		unionC = "mg-union-c" // allowlisted by neither group
		mixA   = "mg-mix-a"
		mixZ   = "mg-mix-z" // on no allowlist; reachable only via the un-guardrailed policy
	)

	priced := func(ids ...string) *[]api.AgentNetworkProviderModel {
		out := make([]api.AgentNetworkProviderModel, 0, len(ids))
		for _, id := range ids {
			out = append(out, api.AgentNetworkProviderModel{Id: id, InputPer1k: 0.001, OutputPer1k: 0.001})
		}
		return &out
	}

	vllm, err := harness.StartVLLM(ctx, srv)
	require.NoError(t, err, "start mock upstream")
	t.Cleanup(func() { _ = vllm.Terminate(context.Background()) })

	mkGroup := func(name string) *api.Group {
		g, gerr := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: name})
		require.NoError(t, gerr, "create group %s", name)
		t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), g.Id) })
		return g
	}
	gUX := mkGroup("e2e-mg-union-x")
	gUY := mkGroup("e2e-mg-union-y")
	gMP := mkGroup("e2e-mg-mix-p")
	gMQ := mkGroup("e2e-mg-mix-q")

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-mg-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{gUX.Id, gUY.Id, gMP.Id, gMQ.Id}, // client in all four groups
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")
	require.NotEmpty(t, sk.Key, "setup key plaintext")

	staticKey := "static-e2e-token"
	enabled := true

	// P1 — union scenario: two restricting policies, one per group.
	p1, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        "e2e-mg-union",
		ProviderId:  "openai_api",
		UpstreamUrl: vllm.URL,
		ApiKey:      &staticKey,
		Enabled:     ptr(true),
		Models:      priced(unionA, unionB, unionC),
	})
	require.NoError(t, err, "create union provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), p1.Id) })

	polUX, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-mg-union-x",
		Enabled:                &enabled,
		SourceGroups:           []string{gUX.Id},
		DestinationProviderIds: []string{p1.Id},
		GuardrailIds:           &[]string{mkAllowGuardrail(t, ctx, "e2e-mg-union-x", unionA).Id},
	})
	require.NoError(t, err, "create union policy X")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), polUX.Id) })

	polUY, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-mg-union-y",
		Enabled:                &enabled,
		SourceGroups:           []string{gUY.Id},
		DestinationProviderIds: []string{p1.Id},
		GuardrailIds:           &[]string{mkAllowGuardrail(t, ctx, "e2e-mg-union-y", unionB).Id},
	})
	require.NoError(t, err, "create union policy Y")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), polUY.Id) })

	// P2 — mixed scenario: one restricting policy + one un-guardrailed policy.
	p2, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        "e2e-mg-mix",
		ProviderId:  "openai_api",
		UpstreamUrl: vllm.URL,
		ApiKey:      &staticKey,
		Enabled:     ptr(true),
		Models:      priced(mixA, mixZ),
	})
	require.NoError(t, err, "create mix provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), p2.Id) })

	polMP, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-mg-mix-p",
		Enabled:                &enabled,
		SourceGroups:           []string{gMP.Id},
		DestinationProviderIds: []string{p2.Id},
		GuardrailIds:           &[]string{mkAllowGuardrail(t, ctx, "e2e-mg-mix-p", mixA).Id},
	})
	require.NoError(t, err, "create mix policy P")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), polMP.Id) })

	polMQ, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-mg-mix-q",
		Enabled:                &enabled,
		SourceGroups:           []string{gMQ.Id},
		DestinationProviderIds: []string{p2.Id}, // NO guardrail -> unrestricted
	})
	require.NoError(t, err, "create mix policy Q")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), polMQ.Id) })

	settings, err := srv.GetSettings(ctx)
	require.NoError(t, err, "read settings")
	require.NotEmpty(t, settings.Endpoint, "endpoint must be assigned")

	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-mg-proxy")
	require.NoError(t, err, "mint proxy token")
	px, err := harness.StartProxy(ctx, srv, proxyToken)
	require.NoError(t, err, "start proxy")
	t.Cleanup(func() { _ = px.Terminate(context.Background()) })

	cl, err := harness.StartClient(ctx, srv, sk.Key)
	require.NoError(t, err, "start client")
	t.Cleanup(func() { _ = cl.Terminate(context.Background()) })

	require.NoError(t, cl.WaitConnected(ctx, 90*time.Second), "client must connect to management")
	proxyIP, err := cl.ResolveProxyIP(ctx, settings.Endpoint)
	require.NoError(t, err, "resolve endpoint to proxy IP")
	if err := cl.WaitProxyPeer(ctx, 180*time.Second); err != nil {
		t.Fatalf("client did not see the proxy peer: %v\n=== proxy logs ===\n%s", err, px.Logs(context.Background()))
	}

	send := func(model string) (int, string) {
		code, body, cerr := cl.Chat(ctx, settings.Endpoint, proxyIP, harness.WireChat, model, "Reply with exactly: pong", "")
		require.NoError(t, cerr, "request must reach the proxy")
		return code, body
	}
	sendUntil200 := func(model string) (int, string) {
		var code int
		var body string
		deadline := time.Now().Add(90 * time.Second)
		for time.Now().Before(deadline) {
			code, body = send(model)
			if code == 200 {
				break
			}
			time.Sleep(5 * time.Second)
		}
		return code, body
	}

	t.Run("union across the user's groups", func(t *testing.T) {
		code, body := sendUntil200(unionA)
		assert.Equal(t, 200, code, "model allowed by group X must be served; body: %s\n=== proxy logs ===\n%s", body, px.Logs(context.Background()))

		code, body = sendUntil200(unionB)
		assert.Equal(t, 200, code, "model allowed by group Y must also be served (union across the user's groups); body: %s", body)

		code, body = send(unionC)
		assert.Equal(t, 403, code, "a model on neither group's allowlist must be denied; body: %s", body)
		assert.Contains(t, body, "llm_policy.model_blocked")
	})

	t.Run("an un-guardrailed group lifts the restriction", func(t *testing.T) {
		code, body := sendUntil200(mixA)
		assert.Equal(t, 200, code, "the restricted group's model must be served; body: %s\n=== proxy logs ===\n%s", body, px.Logs(context.Background()))

		code, body = sendUntil200(mixZ)
		assert.Equal(t, 200, code,
			"a non-allowlisted model must be served because the user is also in a group whose policy has no guardrail; body: %s\n=== proxy logs ===\n%s", body, px.Logs(context.Background()))
	})
}

// mkAllowGuardrail creates a guardrail whose model allowlist is enabled and holds
// exactly the given model, registering cleanup.
func mkAllowGuardrail(t *testing.T, ctx context.Context, name, model string) api.AgentNetworkGuardrail {
	t.Helper()
	var gr api.AgentNetworkGuardrailRequest
	gr.Name = name
	gr.Checks.ModelAllowlist.Enabled = true
	gr.Checks.ModelAllowlist.Models = []string{model}
	g, err := srv.CreateGuardrail(ctx, gr)
	require.NoError(t, err, "create guardrail %s", name)
	t.Cleanup(func() { _ = srv.DeleteGuardrail(context.Background(), g.Id) })
	return g
}
