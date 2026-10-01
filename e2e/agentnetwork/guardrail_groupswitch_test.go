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

// TestGuardrailGroupSwitchTakesEffectAfterTTL proves that moving a peer between
// groups flips its model-allowlist decision once the proxy's tunnel-peer cache
// expires. The peer's groups reach the guardrail via ValidateTunnelPeer, which
// the proxy caches; the switch is invisible until that cache expires. The proxy
// runs with a short NB_PROXY_TUNNEL_CACHE_TTL so the flip happens in seconds
// instead of the 5-minute default.
//
// Setup: one catch-all provider declaring modelA + modelB; polA (grpA -> allow
// modelA) and polB (grpB -> allow modelB). The client starts in grpA. modelA is
// served and modelB denied; after switching the client grpA -> grpB, modelB is
// served and modelA denied. The cross-group deny comes from management's
// per-policy/group CheckLLMPolicyLimits (the proxy backstop carries the union).
func TestGuardrailGroupSwitchTakesEffectAfterTTL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	const (
		modelA = "e2e-model-a"
		modelB = "e2e-model-b"
		// Short tunnel-cache TTL so a group switch propagates in seconds.
		// Exercises the NB_PROXY_TUNNEL_CACHE_TTL override.
		cacheTTL = 3 * time.Second
	)

	vllm, err := harness.StartVLLM(ctx, srv)
	require.NoError(t, err, "start mock upstream")
	t.Cleanup(func() { _ = vllm.Terminate(context.Background()) })

	grpA, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-gswitch-a"})
	require.NoError(t, err, "create group A")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grpA.Id) })

	grpB, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-gswitch-b"})
	require.NoError(t, err, "create group B")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grpB.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-gswitch-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grpA.Id}, // client starts in group A
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")
	require.NotEmpty(t, sk.Key, "setup key plaintext")

	staticKey := "static-e2e-token"
	prov, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        "gswitch",
		ProviderId:  "openai_api",
		UpstreamUrl: vllm.URL,
		ApiKey:      &staticKey,
		Enabled:     ptr(true),
		Models: &[]api.AgentNetworkProviderModel{
			{Id: modelA, InputPer1k: 0.001, OutputPer1k: 0.001},
			{Id: modelB, InputPer1k: 0.001, OutputPer1k: 0.001},
		},
	})
	require.NoError(t, err, "create provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })

	mkGuard := func(name, model string) api.AgentNetworkGuardrail {
		var gr api.AgentNetworkGuardrailRequest
		gr.Name = name
		gr.Checks.ModelAllowlist.Enabled = true
		gr.Checks.ModelAllowlist.Models = []string{model}
		g, gerr := srv.CreateGuardrail(ctx, gr)
		require.NoError(t, gerr, "create guardrail %s", name)
		t.Cleanup(func() { _ = srv.DeleteGuardrail(context.Background(), g.Id) })
		return g
	}
	gA := mkGuard("e2e-gswitch-a", modelA)
	gB := mkGuard("e2e-gswitch-b", modelB)

	enabled := true
	polA, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-gswitch-a",
		Enabled:                &enabled,
		SourceGroups:           []string{grpA.Id},
		DestinationProviderIds: []string{prov.Id},
		GuardrailIds:           &[]string{gA.Id},
	})
	require.NoError(t, err, "create policy A")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), polA.Id) })

	polB, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-gswitch-b",
		Enabled:                &enabled,
		SourceGroups:           []string{grpB.Id},
		DestinationProviderIds: []string{prov.Id},
		GuardrailIds:           &[]string{gB.Id},
	})
	require.NoError(t, err, "create policy B")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), polB.Id) })

	settings, err := srv.GetSettings(ctx)
	require.NoError(t, err, "read settings")
	require.NotEmpty(t, settings.Endpoint, "endpoint must be assigned")

	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-gswitch-proxy")
	require.NoError(t, err, "mint proxy token")
	px, err := harness.StartProxy(ctx, srv, proxyToken, map[string]string{
		"NB_PROXY_TUNNEL_CACHE_TTL": cacheTTL.String(),
	})
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
	sendUntil := func(model string, want int, timeout time.Duration) (int, string) {
		var code int
		var body string
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			code, body = send(model)
			if code == want {
				return code, body
			}
			time.Sleep(2 * time.Second)
		}
		return code, body
	}

	// Phase 1 — client is in group A: modelA served, modelB denied.
	code, body := sendUntil(modelA, 200, 90*time.Second)
	assert.Equal(t, 200, code,
		"group-A model must be served while the client is in group A; body: %s\n=== proxy logs ===\n%s", body, px.Logs(context.Background()))
	code, body = send(modelB)
	assert.Equal(t, 403, code,
		"group-B model must be denied while the client is in group A; body: %s", body)
	assert.Contains(t, body, "llm_policy.model_blocked")

	// Switch the client peer from group A to group B.
	peerID := clientPeerInGroup(t, ctx, grpA.Id)
	_, err = srv.API().Groups.Update(ctx, grpB.Id, api.PutApiGroupsGroupIdJSONRequestBody{
		Name:  grpB.Name,
		Peers: &[]string{peerID},
	})
	require.NoError(t, err, "add peer to group B")
	_, err = srv.API().Groups.Update(ctx, grpA.Id, api.PutApiGroupsGroupIdJSONRequestBody{
		Name:  grpA.Name,
		Peers: &[]string{},
	})
	require.NoError(t, err, "remove peer from group A")

	// Phase 2 — after the short TTL expires the proxy re-validates the peer,
	// sees group B, and the decision flips. Poll to absorb TTL + re-validation.
	code, body = sendUntil(modelB, 200, 60*time.Second)
	assert.Equal(t, 200, code,
		"after the group switch + TTL, the group-B model must be served; body: %s\n=== proxy logs ===\n%s", body, px.Logs(context.Background()))
	code, body = send(modelA)
	assert.Equal(t, 403, code,
		"after the switch, the old group-A model must be denied; body: %s", body)
	assert.Contains(t, body, "llm_policy.model_blocked")
}

// clientPeerInGroup returns the id of the single peer that is a member of the
// given group — the test client. The proxy peer is never added to test groups.
func clientPeerInGroup(t *testing.T, ctx context.Context, groupID string) string {
	t.Helper()
	peers, err := srv.API().Peers.List(ctx)
	require.NoError(t, err, "list peers")
	for _, p := range peers {
		for _, g := range p.Groups {
			if g.Id == groupID {
				return p.Id
			}
		}
	}
	t.Fatalf("no peer found in group %s", groupID)
	return ""
}
