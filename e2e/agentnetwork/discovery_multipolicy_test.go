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
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-disc-mp-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grpMain.Id}, // the client joins grpMain only
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")
	require.NotEmpty(t, sk.Key, "setup key plaintext")

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

	endpoint, proxyIP, cl, px := connectClient(t, ctx, "disc-mp", sk.Key)
	_ = px

	code, body := callUntil(t, func() (int, string, error) {
		return cl.Get(ctx, endpoint, proxyIP, "/v1/models?limit=1000", nil)
	}, 200)
	require.Equal(t, 200, code, "discovery must be served; body: %s", body)

	assert.Contains(t, body, harness.VLLMModel,
		"the model the caller's own policy permits must reach the picker")
	assert.NotContains(t, body, harness.VLLMUnlistedModel,
		"a model only another group's policy permits must not be offered to this caller")
}
