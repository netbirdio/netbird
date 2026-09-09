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

// TestDiscoveryBoundToCallersPolicies covers a model listing on a provider two
// teams reach under different allowlists.
//
// Bounding the listing by the provider's enumerated models alone is not enough
// once more than one policy is in play: the caller would be offered every model
// any team may use, and each one outside their own policy is a request the
// guardrail refuses a moment later — the empty-or-wrong picker this endpoint
// exists to avoid, just moved one level up.
//
// The client joins the main group only. Both models are enumerated by the same
// provider and both are advertised by the upstream, so a listing that leaked
// the other team's model would visibly contain it.
func TestDiscoveryBoundToCallersPolicies(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	vllm, err := harness.StartVLLM(ctx, srv)
	require.NoError(t, err, "start mock upstream")
	t.Cleanup(func() { _ = vllm.Terminate(context.Background()) })

	grpMain, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-disc-mp-main"})
	require.NoError(t, err, "create main group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grpMain.Id) })

	grpOther, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-disc-mp-other"})
	require.NoError(t, err, "create other group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grpOther.Id) })

	ephemeral := false
	mkKey := func(name, groupID string) string {
		sk, kerr := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
			Name:       name,
			Type:       "reusable",
			ExpiresIn:  86400,
			UsageLimit: 0,
			AutoGroups: []string{groupID},
			Ephemeral:  &ephemeral,
		})
		require.NoError(t, kerr, "mint setup key %s", name)
		require.NotEmpty(t, sk.Key, "setup key plaintext")
		return sk.Key
	}
	// One client per group. The second is what makes the first assertion mean
	// something: without a client that DOES see the other team's model, its
	// absence from the main client's listing could equally be a policy that
	// never propagated.
	keyMain := mkKey("e2e-disc-mp-main-client", grpMain.Id)
	keyOther := mkKey("e2e-disc-mp-other-client", grpOther.Id)

	// One provider enumerating both models the upstream advertises, so the
	// listing is narrowed by policy rather than by what the provider serves.
	staticKey := "static-e2e-token"
	prov, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        "e2e-disc-mp",
		ProviderId:  "openai_api",
		UpstreamUrl: vllm.URL,
		ApiKey:      &staticKey,
		Enabled:     ptr(true),
		Models: &[]api.AgentNetworkProviderModel{
			{Id: harness.VLLMModel, InputPer1k: 0.001, OutputPer1k: 0.001},
			{Id: harness.VLLMUnlistedModel, InputPer1k: 0.001, OutputPer1k: 0.001},
		},
	})
	require.NoError(t, err, "create provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })

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
	gMain := mkGuardrail("e2e-disc-mp-main", harness.VLLMModel)
	gOther := mkGuardrail("e2e-disc-mp-other", harness.VLLMUnlistedModel)

	enabled := true
	polMain, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-disc-mp-main",
		Enabled:                &enabled,
		SourceGroups:           []string{grpMain.Id},
		DestinationProviderIds: []string{prov.Id},
		GuardrailIds:           &[]string{gMain.Id},
	})
	require.NoError(t, err, "create main policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), polMain.Id) })

	// The other team's policy, on the same provider, permitting the model the
	// client must never be offered.
	polOther, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-disc-mp-other",
		Enabled:                &enabled,
		SourceGroups:           []string{grpOther.Id},
		DestinationProviderIds: []string{prov.Id},
		GuardrailIds:           &[]string{gOther.Id},
	})
	require.NoError(t, err, "create other policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), polOther.Id) })

	endpoint, proxyIP, clMain, px := connectClient(t, ctx, "disc-mp", keyMain)
	clOther := joinClient(t, ctx, px, endpoint, keyOther)

	listing := func(t *testing.T, cl *harness.Client, ip string) string {
		t.Helper()
		code, body := callUntil(t, func() (int, string, error) {
			return cl.Get(ctx, endpoint, ip, "/v1/models?limit=1000", nil)
		}, 200)
		require.Equal(t, 200, code, "discovery must be served; body: %s", body)
		return body
	}

	otherIP, err := clOther.ResolveProxyIP(ctx, endpoint)
	require.NoError(t, err, "resolve endpoint from the other client")

	// The other team's client first: seeing its own model proves polOther is
	// live, so the main client's listing is narrowed by policy scoping rather
	// than by the other policy having failed to apply at all.
	otherBody := listing(t, clOther, otherIP)
	assert.Contains(t, otherBody, harness.VLLMUnlistedModel,
		"the other group's policy must be in force, or this test proves nothing")
	assert.NotContains(t, otherBody, harness.VLLMModel,
		"and it must not be offered the main group's model either — isolation runs both ways")

	mainBody := listing(t, clMain, proxyIP)
	assert.Contains(t, mainBody, harness.VLLMModel,
		"the model the caller's own policy permits must reach the picker")
	assert.NotContains(t, mainBody, harness.VLLMUnlistedModel,
		"a model only another group's policy permits must not be offered to this caller")
}

// joinClient starts a second tunnel client against an already-running proxy, so
// a test can drive the same endpoint as two different group memberships without
// paying for a second proxy.
func joinClient(t *testing.T, ctx context.Context, px *harness.Proxy, endpoint, setupKey string) *harness.Client {
	t.Helper()

	cl, err := harness.StartClient(ctx, srv, setupKey)
	require.NoError(t, err, "start second client")
	t.Cleanup(func() { _ = cl.Terminate(context.Background()) })

	require.NoError(t, cl.WaitConnected(ctx, 90*time.Second), "second client must connect to management")
	_, err = cl.ResolveProxyIP(ctx, endpoint)
	require.NoError(t, err, "second client could not resolve the endpoint")
	// Guarded rather than passed straight to require: px.Logs pulls the whole
	// proxy container log, which is only worth fetching when the wait failed.
	if err := cl.WaitProxyPeer(ctx, 180*time.Second); err != nil {
		require.NoError(t, err, "second client did not see the proxy peer\n=== proxy logs ===\n%s",
			px.Logs(context.Background()))
	}
	return cl
}
