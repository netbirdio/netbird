//go:build e2e

package agentnetwork

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// streamedModel is priced high enough that a mis-metered request is obvious in
// the recorded cost, and named so it cannot collide with another test's route.
const streamedModel = "e2e-streamed-model"

const (
	streamInRate  = 0.010
	streamOutRate = 0.020
	// The cache-read bucket is priced separately from input, so a run that
	// folded the two together fails the per-bucket assertions below.
	streamCacheReadRate = 0.001
)

// TestStreamingResponseMetersInputTokens is the end-to-end guard for the
// metering bug this endpoint's gateway-protocol work fixed.
//
// On a streamed answer the input-token count exists only in the opening
// message_start event; every later frame reports output. A response read with
// the wrong vendor's parser — the shape a gateway record produces when it names
// one API surface and serves another — never looks at that event, so input
// metered as zero and the bulk of the bill silently vanished. Nothing in the
// suite sent stream: true before this test, so the whole branch went unrun.
//
// The provider points at the mock's streaming listener, which answers every
// request as SSE with token counts that differ from the buffered surface. That
// difference is the point: passing these assertions is only possible if the
// stream accumulator ran.
func TestStreamingResponseMetersInputTokens(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	env := provisionStreamingProvider(t, ctx, "anthropic_api")

	sessionID := fmt.Sprintf("e2e-session-stream-%d", time.Now().UnixNano())
	code, body := chatStreamUntil(t, ctx, env, harness.WireMessages, streamedModel, sessionID)
	require.Equal(t, 200, code, "streamed chat must succeed; body: %s", body)
	assert.Contains(t, body, "message_start",
		"the client must receive the event stream itself, not a buffered rewrite of it")

	row := findAccessLogBySession(t, ctx, sessionID)

	assert.Equal(t, harness.VLLMStreamInputTokens, int(row.InputTokens),
		"input tokens live in message_start; zero here is the bug this test exists for")
	assert.Equal(t, harness.VLLMStreamOutputTokens, int(row.OutputTokens),
		"output tokens ride message_delta and supersede the message_start seed")
	assert.Equal(t, harness.VLLMStreamCacheReadTokens, int(row.CachedInputTokens),
		"the Anthropic cache bucket rides message_start too, and only its own parser reads it")

	// The Anthropic surface bills cache reads additively, so the input bucket
	// prices the full input count rather than a remainder.
	wantInput := float64(harness.VLLMStreamInputTokens) / 1000 * streamInRate
	wantOutput := float64(harness.VLLMStreamOutputTokens) / 1000 * streamOutRate
	assert.InDelta(t, wantInput, row.InputCostUsd, 1e-6, "input cost must price the streamed input tokens")
	assert.InDelta(t, wantOutput, row.OutputCostUsd, 1e-6, "output cost must price the streamed output tokens")
	assert.Greater(t, row.CostUsd, 0.0, "a streamed request must never record as free")
}

// TestStreamingOnGatewayTypedProvider drives the same streamed Anthropic call
// through a provider record whose catalog id names the OpenAI surface — the
// exact misconfiguration that hid the bug, since gateway records commonly pin
// one parser while the upstream serves another shape entirely.
//
// The router must choose the parser from the request path rather than the
// record's provider id, or the Anthropic usage block goes unread and input
// meters at zero all over again.
func TestStreamingOnGatewayTypedProvider(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	env := provisionStreamingProvider(t, ctx, "openai_api")

	sessionID := fmt.Sprintf("e2e-session-stream-gw-%d", time.Now().UnixNano())
	code, body := chatStreamUntil(t, ctx, env, harness.WireMessages, streamedModel, sessionID)
	require.Equal(t, 200, code, "streamed chat through a gateway record must succeed; body: %s", body)

	row := findAccessLogBySession(t, ctx, sessionID)

	assert.Equal(t, harness.VLLMStreamInputTokens, int(row.InputTokens),
		"a record typed openai_api must still read the Anthropic usage block it is actually serving")
	assert.Equal(t, harness.VLLMStreamOutputTokens, int(row.OutputTokens),
		"output tokens must survive the surface mismatch too")
	assert.InDelta(t, float64(harness.VLLMStreamInputTokens)/1000*streamInRate, row.InputCostUsd, 1e-6,
		"the request must be priced on the surface it spoke, not the one the record names")
}

// provisionStreamingProvider brings up the mock, one provider pointed at its
// streaming listener under the given catalog id, a policy authorising it, and a
// connected proxy + client.
func provisionStreamingProvider(t *testing.T, ctx context.Context, catalogID string) pricedEnv {
	t.Helper()

	vllm, err := harness.StartVLLM(ctx, srv)
	require.NoError(t, err, "start mock upstream")
	t.Cleanup(func() { _ = vllm.Terminate(context.Background()) })

	name := "stream-" + catalogID
	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-" + name})
	require.NoError(t, err, "create group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-" + name + "-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")
	require.NotEmpty(t, sk.Key, "setup key plaintext")

	dummyKey := "sk-stream-e2e"
	cacheRead := streamCacheReadRate
	prov, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:        name,
		ProviderId:  catalogID,
		UpstreamUrl: vllm.StreamURL,
		ApiKey:      &dummyKey,
		Enabled:     ptr(true),
		Models: &[]api.AgentNetworkProviderModel{{
			Id:             streamedModel,
			InputPer1k:     streamInRate,
			OutputPer1k:    streamOutRate,
			CacheReadPer1k: &cacheRead,
		}},
	})
	require.NoError(t, err, "create provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })

	enabled := true
	pol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-" + name,
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

	endpoint, proxyIP, cl, px := connectClient(t, ctx, name, sk.Key)
	return pricedEnv{
		providerID: prov.Id,
		groupID:    grp.Id,
		policyID:   pol.Id,
		upstream:   vllm.StreamURL,
		endpoint:   endpoint,
		proxyIP:    proxyIP,
		client:     cl,
		proxy:      px,
	}
}

// chatStreamUntil drives one streamed chat, retrying to absorb the tunnel and
// DNS jitter a first call through a fresh peer can hit.
func chatStreamUntil(t *testing.T, ctx context.Context, env pricedEnv, kind, model, sessionID string) (int, string) {
	t.Helper()
	var code int
	var body string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		c, b, cerr := env.client.ChatStream(ctx, env.endpoint, env.proxyIP, kind, model, "Reply with exactly: pong", sessionID)
		if cerr == nil {
			code, body = c, b
			if code == 200 {
				break
			}
		}
		time.Sleep(5 * time.Second)
	}
	if code != 200 {
		t.Logf("=== proxy logs ===\n%s", env.proxy.Logs(context.Background()))
	}
	return code, body
}
