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

// TestAccessLogErrorAttribution proves the access log says who failed a
// request: a spent policy budget is a policy deny naming the policy, a 401 the
// upstream returned is a provider error, and an upstream the proxy cannot
// reach is a proxy error with the transport detail. One self-signed upstream
// serves all three, told apart by model.
func TestAccessLogErrorAttribution(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	up, err := harness.StartFakeUpstream(ctx, srv)
	require.NoError(t, err, "start self-signed upstream")
	t.Cleanup(func() { _ = up.Terminate(context.Background()) })

	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-error-attribution"})
	require.NoError(t, err, "create group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-error-attribution-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")

	const (
		okModel       = "ok-model"
		budgetModel   = "budget-model"
		rejectedModel = "rejected-model"
		unverifModel  = "unverified-tls-model"
	)

	// The canned reply is 1 input + 1 output token, so at $10 per 1k each a
	// request costs $0.02: twice the $0.01 group cap, spent by the first one.
	newProvider := func(name, model, key string, skipTLS bool) api.AgentNetworkProvider {
		t.Helper()
		p, perr := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
			Name:                name,
			ProviderId:          "openai_api",
			UpstreamUrl:         up.URL,
			ApiKey:              &key,
			Enabled:             ptr(true),
			SkipTlsVerification: ptr(skipTLS),
			Models: &[]api.AgentNetworkProviderModel{
				{Id: model, InputPer1k: 10, OutputPer1k: 10},
			},
		})
		require.NoError(t, perr, "create provider %s", name)
		t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), p.Id) })
		return p
	}
	okProv := newProvider("e2e-attr-ok", okModel, "sk-dummy-e2e", true)
	budgetProv := newProvider("e2e-attr-budget", budgetModel, "sk-dummy-e2e", true)
	rejectedProv := newProvider("e2e-attr-rejected", rejectedModel, harness.FakeUpstreamRejectedKey, true)
	// Verifying the self-signed certificate fails the handshake: a proxy error.
	unverifProv := newProvider("e2e-attr-unverified", unverifModel, "sk-dummy-e2e", false)

	enabled := true
	budgetPol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-attr-budget",
		Enabled:                &enabled,
		SourceGroups:           []string{grp.Id},
		DestinationProviderIds: []string{budgetProv.Id},
		Limits: &api.AgentNetworkPolicyLimits{
			BudgetLimit: api.AgentNetworkPolicyBudgetLimit{Enabled: true, GroupCapUsd: 0.01, WindowSeconds: 3600},
		},
	})
	require.NoError(t, err, "create budget policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), budgetPol.Id) })

	openPol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-attr-uncapped",
		Enabled:                &enabled,
		SourceGroups:           []string{grp.Id},
		DestinationProviderIds: []string{okProv.Id, rejectedProv.Id, unverifProv.Id},
	})
	require.NoError(t, err, "create uncapped policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), openPol.Id) })

	settings, err := srv.GetSettings(ctx)
	require.NoError(t, err, "read settings")

	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-error-attribution-proxy")
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

	chat := func(model, sessionID string) (int, string) {
		code, body, cerr := cl.Chat(ctx, settings.Endpoint, proxyIP, harness.WireChat, model, "Reply with exactly: pong", sessionID)
		require.NoError(t, cerr, "chat %s", sessionID)
		return code, body
	}
	row := func(sessionID string) api.AgentNetworkAccessLog {
		r, ok := lookupAccessLogBySession(ctx, sessionID, accessLogIngestWindow)
		require.True(t, ok, "access-log row for %s must be ingested\n=== proxy logs ===\n%s\n=== management logs ===\n%s",
			sessionID, px.Logs(context.Background()), srv.Logs(context.Background()))
		return r
	}

	// A successful request carries no error attribution. It goes to an
	// uncapped provider, so retrying it to absorb tunnel jitter spends nothing.
	var okSession string
	require.True(t, eventually(ctx, 90*time.Second, func() bool {
		okSession = fmt.Sprintf("e2e-attr-ok-%d", time.Now().UnixNano())
		code, _, cerr := cl.Chat(ctx, settings.Endpoint, proxyIP, harness.WireChat, okModel, "Reply with exactly: pong", okSession)
		return cerr == nil && code == 200
	}), "a request to the uncapped provider must reach the upstream\n=== proxy logs ===\n%s", px.Logs(context.Background()))
	okRow := row(okSession)
	assert.Nil(t, okRow.ErrorSource, "a successful request has no error source")
	assert.Nil(t, okRow.BlockedBy, "a successful request has no blocking policy")

	// Send to the capped provider until one is denied. The first request that
	// reaches the upstream spends the cap; a request curl reports as failed may
	// have been charged too, and usage is recorded after the response, so the
	// test waits for the 403 rather than counting requests.
	var deniedSession string
	require.True(t, eventually(ctx, 120*time.Second, func() bool {
		deniedSession = fmt.Sprintf("e2e-attr-denied-%d", time.Now().UnixNano())
		code, _, cerr := cl.Chat(ctx, settings.Endpoint, proxyIP, harness.WireChat, budgetModel, "Reply with exactly: pong", deniedSession)
		return cerr == nil && code == 403
	}), "a request after the cap is spent must be denied")
	denied := row(deniedSession)
	require.NotNil(t, denied.ErrorSource, "denied row must carry an error source")
	assert.Equal(t, api.AgentNetworkAccessLogErrorSourcePolicy, *denied.ErrorSource)
	require.NotNil(t, denied.BlockedBy, "denied row must name the blocking policy")
	assert.Equal(t, budgetPol.Id, *denied.BlockedBy)
	require.NotNil(t, denied.ErrorDetail, "denied row must carry the cap detail")
	assert.Contains(t, *denied.ErrorDetail, budgetPol.Id, "the detail names the exhausted policy")

	rejectedSession := fmt.Sprintf("e2e-attr-rejected-%d", time.Now().UnixNano())
	code, body := chat(rejectedModel, rejectedSession)
	require.Equal(t, 401, code, "the upstream's own 401 must reach the client; body: %s", body)
	rejected := row(rejectedSession)
	require.NotNil(t, rejected.ErrorSource, "provider-error row must carry an error source")
	assert.Equal(t, api.AgentNetworkAccessLogErrorSourceProvider, *rejected.ErrorSource,
		"a 401 the upstream returned is the provider's, not the proxy's auth")
	assert.Nil(t, rejected.BlockedBy, "nothing blocked a request the provider answered")

	unverifSession := fmt.Sprintf("e2e-attr-unverified-%d", time.Now().UnixNano())
	code, body = chat(unverifModel, unverifSession)
	require.GreaterOrEqual(t, code, 500, "a TLS verification failure is a proxy 5xx; body: %s", body)
	unverif := row(unverifSession)
	require.NotNil(t, unverif.ErrorSource, "proxy-error row must carry an error source")
	assert.Equal(t, api.AgentNetworkAccessLogErrorSourceProxy, *unverif.ErrorSource)
	require.NotNil(t, unverif.ErrorDetail, "proxy-error row must carry the transport detail")
	assert.Contains(t, *unverif.ErrorDetail, "certificate", "the detail is the handshake failure")
}
