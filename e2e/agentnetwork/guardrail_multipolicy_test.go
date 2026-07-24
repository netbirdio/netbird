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

// TestGuardrailMultiPolicyModelAllowlist is the end-to-end regression guard for
// the multi-policy interactions of the model-allowlist guardrail: what happens
// when several enabled policies govern an account and some carry a guardrail
// while others don't. The earlier implementation merged every policy's allowlist
// into ONE account-wide union enforced flat on every request, which produced two
// defects this test pins:
//
//   - false-ALLOW (cross-group leak): a model allowlisted only for another
//     group's policy became usable by any caller, because the union ignored
//     which policy/group actually authorised the request; and
//   - false-DENY: a policy with NO guardrail (intended unrestricted) still had
//     its traffic blocked by some other policy's allowlist.
//
// The fix scopes enforcement to the matched policy/group in management
// (SelectPolicyForRequest) with a per-provider fail-closed backstop at the
// proxy. The account here has one client in grpMain and three policies over two
// catch-all upstreams (the mock vLLM answers any model 200, so a 403 can only be
// a policy decision, never a routing miss):
//
//   - polMain : grpMain  -> pRestricted, guardrail allowlisting modelSelected
//   - polOther: grpOther -> pRestricted, guardrail allowlisting modelOther
//   - polOpen : grpMain  -> pOpen,       NO guardrail (unrestricted)
//
// Providers declare their models so routing is deterministic. Over the tunnel,
// as the grpMain client:
//
//   - modelSelected on pRestricted is served (200) — allowed by grpMain's policy;
//   - modelOther on pRestricted is denied 403 (llm_policy.model_blocked) — it is
//     allowlisted only for grpOther and must NOT leak to grpMain; and
//   - openModel on pOpen is served (200) — the un-guardrailed policy leaves that
//     provider unrestricted and must NOT be blocked by another policy's list.
//
// Under the old account-wide union the middle case returned 200 (the leak) and
// the last case returned 403 (the false-deny); both are inverted here.
func TestGuardrailMultiPolicyModelAllowlist(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	const (
		modelSelected = "e2e-selected"
		modelOther    = "e2e-other"
		openModel     = "e2e-open"
	)

	vllm, err := harness.StartVLLM(ctx, srv)
	require.NoError(t, err, "start mock upstream")
	t.Cleanup(func() { _ = vllm.Terminate(context.Background()) })

	grpMain, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-guardrail-mp-main"})
	require.NoError(t, err, "create main group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grpMain.Id) })

	grpOther, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-guardrail-mp-other"})
	require.NoError(t, err, "create other group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grpOther.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-guardrail-mp-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grpMain.Id}, // client joins grpMain only
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")
	require.NotEmpty(t, sk.Key, "setup key plaintext")

	staticKey := "static-e2e-token"
	models := func(ids ...string) *[]api.AgentNetworkProviderModel {
		out := make([]api.AgentNetworkProviderModel, 0, len(ids))
		for _, id := range ids {
			out = append(out, api.AgentNetworkProviderModel{Id: id, InputPer1k: 0.001, OutputPer1k: 0.001})
		}
		return &out
	}

	// pRestricted declares the two guardrailed models so routing is deterministic
	// (model -> provider). Created first, so it carries the bootstrap cluster.
	pRestricted, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:             "restricted",
		ProviderId:       "openai_api",
		UpstreamUrl:      vllm.URL,
		ApiKey:           &staticKey,
		Enabled:          ptr(true),
		Models:           models(modelSelected, modelOther),
		BootstrapCluster: ptr(harness.AgentNetworkCluster),
	})
	require.NoError(t, err, "create restricted provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), pRestricted.Id) })

	pOpen, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        "open",
		ProviderId:  "openai_api",
		UpstreamUrl: vllm.URL,
		ApiKey:      &staticKey,
		Enabled:     ptr(true),
		Models:      models(openModel),
	})
	require.NoError(t, err, "create open provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), pOpen.Id) })

	mkGuardrail := func(name, model string) api.AgentNetworkGuardrail {
		var gr api.AgentNetworkGuardrailRequest
		gr.Name = name
		gr.Checks.ModelAllowlist.Enabled = true
		gr.Checks.ModelAllowlist.Models = []string{model}
		g, gerr := srv.CreateGuardrail(ctx, gr)
		require.NoError(t, gerr, "create guardrail %s", name)
		t.Cleanup(func() { _ = srv.DeleteGuardrail(context.Background(), g.Id) })
		return g
	}
	gMain := mkGuardrail("e2e-guardrail-mp-main", modelSelected)
	gOther := mkGuardrail("e2e-guardrail-mp-other", modelOther)

	enabled := true
	// polMain: grpMain restricted to modelSelected on pRestricted.
	polMain, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-guardrail-mp-main",
		Enabled:                &enabled,
		SourceGroups:           []string{grpMain.Id},
		DestinationProviderIds: []string{pRestricted.Id},
		GuardrailIds:           &[]string{gMain.Id},
	})
	require.NoError(t, err, "create main policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), polMain.Id) })

	// polOther: grpOther restricted to modelOther on the SAME provider. The
	// client is not in grpOther, so modelOther must never be usable by it.
	polOther, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-guardrail-mp-other",
		Enabled:                &enabled,
		SourceGroups:           []string{grpOther.Id},
		DestinationProviderIds: []string{pRestricted.Id},
		GuardrailIds:           &[]string{gOther.Id},
	})
	require.NoError(t, err, "create other policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), polOther.Id) })

	// polOpen: grpMain on pOpen with NO guardrail — unrestricted.
	polOpen, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-guardrail-mp-open",
		Enabled:                &enabled,
		SourceGroups:           []string{grpMain.Id},
		DestinationProviderIds: []string{pOpen.Id},
	})
	require.NoError(t, err, "create open policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), polOpen.Id) })

	settings, err := srv.GetSettings(ctx)
	require.NoError(t, err, "read settings")
	require.NotEmpty(t, settings.Endpoint, "endpoint must be assigned")

	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-guardrail-mp-proxy")
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
	// sendUntil200 absorbs first-call tunnel/DNS jitter on the freshly warmed tunnel.
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

	t.Run("selected model allowed for its group", func(t *testing.T) {
		code, body := sendUntil200(modelSelected)
		assert.Equal(t, 200, code,
			"grpMain's allowlisted model must be served; body: %s\n=== proxy logs ===\n%s", body, px.Logs(context.Background()))
	})

	t.Run("other group's model does not leak", func(t *testing.T) {
		// modelOther is allowlisted only for grpOther. The grpMain client must be
		// denied by management's per-policy/group check — not waved through by an
		// account-wide union. This is the security-critical wrong-ALLOW guard.
		code, body := send(modelOther)
		assert.Equal(t, 403, code,
			"another group's allowlisted model must be denied for this caller; body: %s\n=== proxy logs ===\n%s", body, px.Logs(context.Background()))
		assert.Contains(t, body, "llm_policy.model_blocked",
			"denial must be a model-allowlist decision; body: %s", body)
	})

	t.Run("unguarded policy leaves its provider unrestricted", func(t *testing.T) {
		// polOpen carries no guardrail, so pOpen is unrestricted for grpMain. The
		// old account-wide union would have blocked openModel (it is on no
		// allowlist); it must now be served — the false-DENY guard.
		code, body := sendUntil200(openModel)
		assert.Equal(t, 200, code,
			"an un-guardrailed policy's provider must not be blocked by another policy's allowlist; body: %s\n=== proxy logs ===\n%s", body, px.Logs(context.Background()))
	})
}
