//go:build e2e

package agentnetwork

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestVLLMProvider proves the proxy supports a self-hosted vLLM backend. vLLM is
// OpenAI-compatible, so it uses the "vllm" catalog entry (KindCustom) and is
// reached over plain HTTP — no TLS anywhere on the path:
//
//	client --tunnel--> netbird proxy --http--> vllm (:8000, OpenAI-compatible)
//
// The mock vLLM server answers /v1/chat/completions with an OpenAI-shaped
// completion carrying a non-zero usage block. The test asserts the chat returns
// 200 with the completion, that the request is recorded in the access log by its
// session id, and that vLLM's usage block is metered into a consumption row —
// which together prove request routing, response parsing, and token accounting
// all work for a self-hosted OpenAI-compatible provider.
//
// It needs no external credentials (the mock ignores auth), so it always runs.
func TestVLLMProvider(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	vllm, err := harness.StartVLLM(ctx, srv)
	require.NoError(t, err, "start mock vLLM server")
	t.Cleanup(func() { _ = vllm.Terminate(context.Background()) })

	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-vllm"})
	require.NoError(t, err, "create group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-vllm-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")
	require.NotEmpty(t, sk.Key, "setup key plaintext")

	// vLLM provider pointed at the mock over plain HTTP. The mock ignores auth,
	// so a dummy key satisfies the "Bearer ${API_KEY}" template. The served model
	// is enumerated so the router dispatches this model string to this provider.
	dummyKey := "sk-vllm-e2e"
	prov, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:             "vllm",
		ProviderId:       "vllm",
		UpstreamUrl:      vllm.URL,
		ApiKey:           &dummyKey,
		Enabled:          ptr(true),
		BootstrapCluster: ptr(harness.AgentNetworkCluster),
		Models: &[]api.AgentNetworkProviderModel{
			{Id: harness.VLLMModel, InputPer1k: 0.001, OutputPer1k: 0.002},
		},
	})
	require.NoError(t, err, "create vllm provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })

	// Token limit far above the handful of tokens this test drives, so it never
	// blocks but switches on usage metering — the switch that makes consumption
	// rows get recorded.
	enabled := true
	pol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-vllm-allow",
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

	settings, err := srv.GetSettings(ctx)
	require.NoError(t, err, "read settings")
	require.NotEmpty(t, settings.Endpoint, "endpoint must be assigned")

	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-vllm-proxy")
	require.NoError(t, err, "mint proxy token")
	px, err := harness.StartProxy(ctx, srv, proxyToken)
	require.NoError(t, err, "start proxy")
	t.Cleanup(func() { _ = px.Terminate(context.Background()) })

	cl, err := harness.StartClient(ctx, srv, sk.Key)
	require.NoError(t, err, "start client")
	t.Cleanup(func() { _ = cl.Terminate(context.Background()) })

	require.NoError(t, cl.WaitConnected(ctx, 90*time.Second), "client must connect to management")
	if err := cl.WaitProxyPeer(ctx, 180*time.Second); err != nil {
		t.Fatalf("client did not see the proxy peer: %v\n=== proxy logs ===\n%s", err, px.Logs(context.Background()))
	}
	proxyIP, err := cl.ResolveProxyIP(ctx, settings.Endpoint)
	require.NoError(t, err, "resolve endpoint to proxy IP")

	before, _ := srv.ListAccessLogs(ctx)
	sessionID := "e2e-session-vllm"

	// Retry to absorb tunnel/DNS jitter on the first call.
	var code int
	var body string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		c, b, cerr := cl.Chat(ctx, settings.Endpoint, proxyIP, harness.WireChat, harness.VLLMModel, "Reply with exactly: pong", sessionID)
		if cerr == nil {
			code, body = c, b
			if code == 200 {
				break
			}
		}
		time.Sleep(5 * time.Second)
	}
	require.Equal(t, 200, code,
		"chat through the vLLM provider must return 200; body: %s\n=== vllm logs ===\n%s\n=== proxy logs ===\n%s",
		body, vllm.Logs(context.Background()), px.Logs(context.Background()))
	require.True(t, strings.Contains(body, "chat.completion"),
		"body should be an OpenAI-compatible chat completion; got: %s", body)

	// The request must surface as an access-log row carrying our session id.
	require.Eventually(t, func() bool {
		logs, lerr := srv.ListAccessLogs(ctx)
		return lerr == nil && logs.TotalRecords > before.TotalRecords
	}, 30*time.Second, 2*time.Second, "an access-log row should be ingested for the vLLM provider")

	require.Eventually(t, func() bool {
		logs, lerr := srv.ListAccessLogs(ctx)
		if lerr != nil {
			return false
		}
		for _, r := range logs.Data {
			if r.SessionId != nil && *r.SessionId == sessionID {
				return true
			}
		}
		return false
	}, 30*time.Second, 2*time.Second, "session id %q must be recorded in an access-log row", sessionID)

	// vLLM's usage block (prompt_tokens=11, completion_tokens=2) must be parsed
	// and metered into a consumption row with positive token counts.
	require.Eventually(t, func() bool {
		rows, lerr := srv.ListConsumption(ctx)
		if lerr != nil {
			return false
		}
		for _, r := range rows {
			if r.TokensInput > 0 && r.TokensOutput > 0 {
				return true
			}
		}
		return false
	}, 60*time.Second, 3*time.Second, "vLLM usage must be metered into a consumption row")
}
