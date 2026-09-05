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

// The cases in this file cover behaviour that arrived from code review, after
// the gateway-protocol end-to-end tests were written. Each had unit coverage
// only; none needed a new harness capability, which is why they belong here
// rather than on a manual checklist.

// TestNonInferenceEndpointsAreAuthorised covers the two review findings on the
// endpoints that carry no body: the per-model lookup must be authorised
// against the same allowlist that bounds the listing beside it, and only a read
// method may claim the non-inference exemption that skips the token pre-flight.
func TestNonInferenceEndpointsAreAuthorised(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	env := provisionDiscoveryProvider(t, ctx)

	t.Run("lookup of an authorised model succeeds", func(t *testing.T) {
		code, body := callUntil(t, func() (int, string, error) {
			return env.client.Get(ctx, env.endpoint, env.proxyIP, "/v1/models/"+harness.VLLMModel, nil)
		}, 200)
		assert.Equal(t, 200, code, "an allowlisted model must remain reachable; body: %s", body)
	})

	t.Run("lookup of an unauthorised model is refused", func(t *testing.T) {
		code, body, err := env.client.Get(ctx, env.endpoint, env.proxyIP, "/v1/models/"+harness.VLLMUnlistedModel, nil)
		require.NoError(t, err, "request must reach the proxy")
		assert.Equal(t, 403, code,
			"a model the policy does not authorise must not be confirmed by the detail lookup; body: %s", body)
	})

	// A write must not claim the exemption that lets the listing skip the token
	// pre-flight. The body names no model on purpose: that is what a request
	// probing for the exemption looks like, and it is the case the method gate
	// exists to refuse. (A POST that does name a model is a different thing —
	// it routes and meters as the inference request it is.)
	for _, path := range []string{"/v1/models", "/v1/models/" + harness.VLLMModel, "/api/hello"} {
		t.Run("write to "+path+" is refused", func(t *testing.T) {
			code, body, err := env.client.PostJSON(ctx, env.endpoint, env.proxyIP, path,
				`{"messages":[{"role":"user","content":"hi"}]}`, nil)
			require.NoError(t, err, "request must reach the proxy")
			assert.NotEqual(t, 200, code,
				"a write to a non-inference path must not be served unmetered; body: %s", body)
		})
	}

	// A request carrying the sub-agent attribution headers must still be served
	// and metered normally. Asserting the ids themselves is not possible yet:
	// the parser lifts them onto the request's metadata, but nothing persists
	// them, so they have no queryable surface to check against.
	t.Run("sub-agent headers do not disturb the request", func(t *testing.T) {
		sessionID := fmt.Sprintf("e2e-session-agentid-%d", time.Now().UnixNano())
		code, body, err := env.client.PostJSON(ctx, env.endpoint, env.proxyIP, "/v1/chat/completions",
			fmt.Sprintf(`{"model":%q,"messages":[{"role":"user","content":"Reply with exactly: pong"}]}`, harness.VLLMModel),
			[]string{
				"x-session-id: " + sessionID,
				"x-claude-code-agent-id: agent-child-7",
				"x-claude-code-parent-agent-id: agent-root-1",
			})
		require.NoError(t, err, "request must reach the proxy")
		require.Equal(t, 200, code, "the request must succeed; body: %s", body)

		row := findAccessLogBySession(t, ctx, sessionID)
		assert.Positive(t, row.InputTokens, "the request must still be metered normally")
	})
}

// TestDatedModelIdRouting covers both halves of the dated-id rule that review
// tightened: a dated id still reaches an undated registration, but a route
// pinned to one dated build must never serve a different one.
func TestDatedModelIdRouting(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	const (
		undated = "claude-sonnet-9"
		datedA  = "claude-sonnet-9-20250101"
		datedB  = "claude-sonnet-9-20250202"
	)

	t.Run("a dated id reaches its undated registration", func(t *testing.T) {
		env := provisionModelProvider(t, ctx, "dated-undated", "anthropic_api", undated)

		sessionID := fmt.Sprintf("e2e-session-dated-%d", time.Now().UnixNano())
		code, body := callUntil(t, func() (int, string, error) {
			return env.client.Chat(ctx, env.endpoint, env.proxyIP, harness.WireMessages, datedA, "Reply with exactly: pong", sessionID)
		}, 200)
		require.Equal(t, 200, code, "a pinned release of a registered family must route; body: %s", body)

		row := findAccessLogBySession(t, ctx, sessionID)
		assert.Positive(t, row.InputTokens, "the dated request must price at the registered rate, not zero")
	})

	t.Run("a route pinned to one dated build refuses another", func(t *testing.T) {
		env := provisionModelProvider(t, ctx, "dated-pinned", "anthropic_api", datedA)

		code, body := callUntil(t, func() (int, string, error) {
			return env.client.Chat(ctx, env.endpoint, env.proxyIP, harness.WireMessages, datedA, "Reply with exactly: pong", "")
		}, 200)
		require.Equal(t, 200, code, "the exact dated id must still route; body: %s", body)

		code, body, err := env.client.Chat(ctx, env.endpoint, env.proxyIP, harness.WireMessages, datedB, "Reply with exactly: pong", "")
		require.NoError(t, err, "request must reach the proxy")
		assert.Equal(t, 403, code,
			"a provider pinned to one dated build must not serve another; body: %s", body)
	})
}

// TestBedrockInferenceProfilesReachTheUpstream covers the startup lookup a
// Bedrock client makes. The proxy forwards it to the configured upstream rather
// than denying it, so what comes back is the upstream's answer — never a
// NetBird policy rejection.
func TestBedrockInferenceProfilesReachTheUpstream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	env := provisionModelProvider(t, ctx, "infprofiles", "bedrock_api", "anthropic.claude-sonnet-5")

	code, body := callUntil(t, func() (int, string, error) {
		return env.client.Get(ctx, env.endpoint, env.proxyIP, "/inference-profiles", nil)
	}, 200)

	assert.Equal(t, 200, code, "the lookup must reach the upstream; body: %s", body)
	assert.NotContains(t, body, "llm_policy.",
		"the proxy must not answer a control-plane lookup with a policy denial")
	assert.Contains(t, body, "inferenceProfileSummaries",
		"the upstream's own answer must come back untouched")
}

// provisionDiscoveryProvider brings up one mock-backed provider enumerating a
// single model, with an allowlist guardrail in effect, plus a connected client.
func provisionDiscoveryProvider(t *testing.T, ctx context.Context) pricedEnv {
	t.Helper()
	env := provisionModelProvider(t, ctx, "noninference", "openai_api", harness.VLLMModel)

	var gr api.AgentNetworkGuardrailRequest
	gr.Name = "e2e-noninference-allowlist-" + fmt.Sprint(time.Now().UnixNano())
	gr.Checks.ModelAllowlist.Enabled = true
	gr.Checks.ModelAllowlist.Models = []string{harness.VLLMModel}
	guard, err := srv.CreateGuardrail(ctx, gr)
	require.NoError(t, err, "create guardrail")
	t.Cleanup(func() { _ = srv.DeleteGuardrail(context.Background(), guard.Id) })

	enabled := true
	_, err = srv.UpdatePolicy(ctx, env.policyID, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-noninference",
		Enabled:                &enabled,
		SourceGroups:           []string{env.groupID},
		DestinationProviderIds: []string{env.providerID},
		GuardrailIds:           &[]string{guard.Id},
	})
	require.NoError(t, err, "attach guardrail to policy")
	return env
}

// provisionModelProvider brings up the mock, one provider under the given
// catalog id enumerating exactly one model, an authorising policy, and a
// connected proxy + client.
func provisionModelProvider(t *testing.T, ctx context.Context, name, catalogID, model string) pricedEnv {
	t.Helper()

	vllm, err := harness.StartVLLM(ctx, srv)
	require.NoError(t, err, "start mock upstream")
	t.Cleanup(func() { _ = vllm.Terminate(context.Background()) })

	suffix := strings.ToLower(name)
	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-gwr-" + suffix})
	require.NoError(t, err, "create group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-gwr-" + suffix + "-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")
	require.NotEmpty(t, sk.Key, "setup key plaintext")

	dummyKey := "sk-gwr-e2e"
	prov, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        "e2e-gwr-" + suffix,
		ProviderId:  catalogID,
		UpstreamUrl: vllm.URL,
		ApiKey:      &dummyKey,
		Enabled:     ptr(true),
		Models: &[]api.AgentNetworkProviderModel{
			{Id: model, InputPer1k: 0.001, OutputPer1k: 0.002},
		},
	})
	require.NoError(t, err, "create provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })

	enabled := true
	pol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-gwr-" + suffix,
		Enabled:                &enabled,
		SourceGroups:           []string{grp.Id},
		DestinationProviderIds: []string{prov.Id},
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

	endpoint, proxyIP, cl, px := connectClient(t, ctx, "gwr-"+suffix, sk.Key)
	return pricedEnv{
		providerID: prov.Id,
		groupID:    grp.Id,
		policyID:   pol.Id,
		upstream:   vllm.URL,
		endpoint:   endpoint,
		proxyIP:    proxyIP,
		client:     cl,
		proxy:      px,
	}
}
