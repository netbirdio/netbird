package llm_router

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/middleware"
)

// bedrockRoute is a Bedrock provider whose listing lives on the control plane
// while inference goes to the runtime host — the split this file is about.
func bedrockRoute(models []string, policies []ModelPolicyRule) ProviderRoute {
	return ProviderRoute{
		ID:              "prov-bedrock",
		Bedrock:         true,
		Models:          models,
		ModelPolicies:   policies,
		UpstreamScheme:  "https",
		UpstreamHost:    "bedrock-runtime.eu-central-1.amazonaws.com",
		DiscoveryHost:   "bedrock.eu-central-1.amazonaws.com",
		AuthHeaderName:  "Authorization",
		AuthHeaderValue: "Bearer aws-token",
		AllowedGroupIDs: []string{defaultTestGroup},
	}
}

func getInput(path string) *middleware.Input {
	return &middleware.Input{
		Slot:       middleware.SlotOnRequest,
		Method:     http.MethodGet,
		URL:        "https://endpoint.netbird.local" + path,
		UserGroups: []string{defaultTestGroup},
	}
}

// TestBedrockListingGoesToTheControlPlane is the whole point of DiscoveryHost.
// ListInferenceProfiles is not an operation bedrock-runtime implements — it
// answers <UnknownOperationException/> — so a listing forwarded to the
// inference upstream can only 404, however well it is routed.
func TestBedrockListingGoesToTheControlPlane(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{bedrockRoute(nil, nil)}})

	out, err := mw.Invoke(context.Background(), getInput("/inference-profiles"))
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, out.Decision)
	require.NotNil(t, out.Mutations)
	require.NotNil(t, out.Mutations.RewriteUpstream)

	assert.Equal(t, "bedrock.eu-central-1.amazonaws.com", out.Mutations.RewriteUpstream.Host)
}

// TestBedrockInferenceStillGoesToTheRuntimeHost is the other half: the
// redirect must apply to the listing alone. Sending an InvokeModel call to the
// control plane would break every Bedrock request in the account.
func TestBedrockInferenceStillGoesToTheRuntimeHost(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{bedrockRoute(nil, nil)}})

	in := newInputWithModelAndURL("anthropic.claude-haiku-4-5",
		"https://endpoint.netbird.local/model/eu.anthropic.claude-haiku-4-5-20251001-v1:0/invoke")
	out, err := mw.Invoke(context.Background(), in)
	require.NoError(t, err)
	require.Equal(t, middleware.DecisionAllow, out.Decision)
	require.NotNil(t, out.Mutations.RewriteUpstream)

	assert.Equal(t, "bedrock-runtime.eu-central-1.amazonaws.com", out.Mutations.RewriteUpstream.Host)
}

// TestIsListingPath guards the narrower reading of "model-less". Both the
// upstream redirect and the policy bound key on this, and the warming probe
// must be excluded from both: it carries no listing to filter, and pointing it
// at the control plane would warm a pool the inference requests never use.
func TestIsListingPath(t *testing.T) {
	for path, want := range map[string]bool{
		"/v1/models":                  true,
		"/inference-profiles":         true,
		"/bedrock/inference-profiles": true,
		"/api/hello":                  false,
		"/v1/models/gpt-4o":           false, // the per-model lookup, routed elsewhere
		"/v1/chat/completions":        false,
	} {
		t.Run(path, func(t *testing.T) {
			assert.Equal(t, want, isListingPath(path))
		})
	}
}

// TestBedrockListingIsBoundByPolicy covers the case that was previously
// unreachable: filtering keyed on /v1/models alone, so a Bedrock listing was
// routed but never narrowed to what the caller may use.
func TestBedrockListingIsBoundByPolicy(t *testing.T) {
	route := bedrockRoute(
		[]string{"eu.anthropic.claude-haiku-4-5-20251001-v1:0", "eu.anthropic.claude-sonnet-4-6"},
		[]ModelPolicyRule{{
			GroupIDs: []string{defaultTestGroup},
			// A guardrail allowlist names the catalog key, which is the form an
			// operator picks in the UI — not the region-prefixed wire id the
			// record registers.
			Models: []string{"anthropic.claude-haiku-4-5"},
		}},
	)
	mw := New(Config{Providers: []ProviderRoute{route}})

	out, err := mw.Invoke(context.Background(), getInput("/inference-profiles"))
	require.NoError(t, err)
	require.NotNil(t, out.Mutations.RewriteUpstream)

	// Exact-string intersection would find nothing here and bound the listing
	// to empty, handing the caller a picker with no models on a provider that
	// works perfectly well.
	assert.Equal(t, []string{"eu.anthropic.claude-haiku-4-5-20251001-v1:0"},
		out.Mutations.RewriteUpstream.DiscoveryModels)
}

// TestBedrockListingWithoutADiscoveryHostFallsThrough keeps a proxied or
// self-hosted Bedrock endpoint working: the synthesiser emits no discovery
// host for one, and the listing must then go to the configured upstream rather
// than nowhere.
func TestBedrockListingWithoutADiscoveryHostFallsThrough(t *testing.T) {
	route := bedrockRoute(nil, nil)
	route.UpstreamHost = "bedrock.internal.example.com"
	route.DiscoveryHost = ""
	mw := New(Config{Providers: []ProviderRoute{route}})

	out, err := mw.Invoke(context.Background(), getInput("/inference-profiles"))
	require.NoError(t, err)
	require.NotNil(t, out.Mutations.RewriteUpstream)

	assert.Equal(t, "bedrock.internal.example.com", out.Mutations.RewriteUpstream.Host)
}

// TestBedrockProfileDetailHonoursTheModelTable covers GetInferenceProfile,
// which the listing filter cannot help with: it answers for one profile with a
// single object, not a set, so nothing narrows it on the way back. Authorising
// it by provider type alone would let any caller with a Bedrock route read the
// full configuration of every profile in the account.
//
// Both registration spellings are exercised, because a record may carry the
// raw profile id AWS issues or the catalog key it reduces to.
func TestBedrockProfileDetailHonoursTheModelTable(t *testing.T) {
	const permitted = "eu.anthropic.claude-sonnet-5-20260514-v1:0"

	for _, registered := range []string{permitted, "anthropic.claude-sonnet-5"} {
		t.Run(registered, func(t *testing.T) {
			mw := New(Config{Providers: []ProviderRoute{bedrockRoute([]string{registered}, nil)}})

			out, err := mw.Invoke(context.Background(), getInput("/inference-profiles/"+permitted))
			require.NoError(t, err)
			assert.Equal(t, middleware.DecisionAllow, out.Decision,
				"a profile the record registers must still resolve")

			denied, err := mw.Invoke(context.Background(),
				getInput("/inference-profiles/eu.anthropic.claude-opus-5-20260514-v1:0"))
			require.NoError(t, err)
			assert.Equal(t, middleware.DecisionDeny, denied.Decision,
				"a profile outside the record's models must not be readable")
		})
	}
}

// TestBedrockProfileListingStaysModelLess pins the other half: the listing
// names no profile, so it must not be judged against the model table. It is
// bounded by DiscoveryModels in the response instead, and denying it here
// would take model discovery away from exactly the records that enumerate
// their models.
func TestBedrockProfileListingStaysModelLess(t *testing.T) {
	mw := New(Config{Providers: []ProviderRoute{bedrockRoute([]string{"anthropic.claude-sonnet-5"}, nil)}})

	out, err := mw.Invoke(context.Background(), getInput("/inference-profiles"))
	require.NoError(t, err)
	assert.Equal(t, middleware.DecisionAllow, out.Decision)
}
