//go:build e2e

package agentnetwork

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// TestProviderSkipTLSVerification proves skip_tls_verification is per-provider:
// two providers share one self-signed upstream, one skipping TLS verification
// and one not. The skip=true provider's chat reaches the upstream and returns
// 200; the skip=false provider's chat fails at the TLS handshake — same
// upstream, opposite outcome. This is the behaviour a target-level flag could
// not give, since all of an account's providers share one synthesised target.
func TestProviderSkipTLSVerification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	up, err := harness.StartFakeUpstream(ctx, srv)
	require.NoError(t, err, "start self-signed upstream")
	t.Cleanup(func() { _ = up.Terminate(context.Background()) })

	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-skiptls"})
	require.NoError(t, err, "create group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-skiptls-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")
	require.NotEmpty(t, sk.Key, "setup key plaintext")

	const (
		insecureModel = "insecure-model"
		secureModel   = "secure-model"
	)

	// Two providers on the SAME self-signed upstream, distinguished only by their
	// skip_tls_verification and a unique model string so the router picks each
	// unambiguously.
	newReq := func(name, model string, skip bool) api.AgentNetworkProviderRequest {
		key := "sk-dummy-e2e"
		return api.AgentNetworkProviderRequest{
			Name:                name,
			ProviderId:          "openai_api",
			UpstreamUrl:         up.URL,
			ApiKey:              &key,
			Enabled:             ptr(true),
			SkipTlsVerification: ptr(skip),
			Models: &[]api.AgentNetworkProviderModel{
				{Id: model, InputPer1k: 0.001, OutputPer1k: 0.002},
			},
		}
	}

	// First create bootstraps the account cluster.
	insecureReq := newReq("skip-tls", insecureModel, true)
	insecureReq.BootstrapCluster = ptr(harness.AgentNetworkCluster)
	insecureProv, err := srv.CreateProvider(ctx, insecureReq)
	require.NoError(t, err, "create skip-tls provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), insecureProv.Id) })
	require.True(t, insecureProv.SkipTlsVerification, "response must echo skip_tls_verification=true")

	secureProv, err := srv.CreateProvider(ctx, newReq("verify-tls", secureModel, false))
	require.NoError(t, err, "create verify-tls provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), secureProv.Id) })
	require.False(t, secureProv.SkipTlsVerification, "response must echo skip_tls_verification=false")

	enabled := true
	pol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-skiptls-allow",
		Enabled:                &enabled,
		SourceGroups:           []string{grp.Id},
		DestinationProviderIds: []string{insecureProv.Id, secureProv.Id},
	})
	require.NoError(t, err, "create policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), pol.Id) })

	settings, err := srv.GetSettings(ctx)
	require.NoError(t, err, "read settings")
	require.NotEmpty(t, settings.Endpoint, "endpoint must be assigned")

	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-skiptls-proxy")
	require.NoError(t, err, "mint proxy token")
	px, err := harness.StartProxy(ctx, srv, proxyToken)
	require.NoError(t, err, "start proxy")
	t.Cleanup(func() { _ = px.Terminate(context.Background()) })

	cl, err := harness.StartClient(ctx, srv, sk.Key)
	require.NoError(t, err, "start client")
	t.Cleanup(func() { _ = cl.Terminate(context.Background()) })

	require.NoError(t, cl.WaitConnected(ctx, 90*time.Second), "client must connect to management")
	// Probe first: the GET resolves the endpoint (DNS error fails) and its first packet wakes the lazy proxy peer, so WaitProxyPeer sees it connected; any HTTP status counts.
	proxyIP, err := cl.ResolveProxyIP(ctx, settings.Endpoint)
	require.NoError(t, err, "resolve endpoint to proxy IP")
	if err := cl.WaitProxyPeer(ctx, 180*time.Second); err != nil {
		t.Fatalf("client did not see the proxy peer: %v\n=== proxy logs ===\n%s", err, px.Logs(context.Background()))
	}

	// Positive: skip=true reaches the self-signed upstream. Retry to absorb
	// tunnel/DNS jitter on the first call; success also proves the path works.
	var code int
	var body string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		c, b, cerr := cl.Chat(ctx, settings.Endpoint, proxyIP, harness.WireChat, insecureModel, "Reply with exactly: pong", "e2e-skiptls-insecure")
		if cerr == nil {
			code, body = c, b
			if code == 200 {
				break
			}
		}
		time.Sleep(5 * time.Second)
	}
	require.Equal(t, 200, code,
		"skip_tls_verification=true must reach the self-signed upstream; body: %s\n=== upstream logs ===\n%s\n=== proxy logs ===\n%s",
		body, up.Logs(context.Background()), px.Logs(context.Background()))

	// Negative: skip=false must fail the TLS handshake to the SAME upstream. The
	// path is already proven working, so a non-200 here is the cert rejection.
	secureCode, secureBody, cerr := cl.Chat(ctx, settings.Endpoint, proxyIP, harness.WireChat, secureModel, "Reply with exactly: pong", "e2e-skiptls-secure")
	require.NoError(t, cerr, "the chat call itself must complete (proxy returns an error status, not a transport error)")
	require.NotEqual(t, 200, secureCode,
		"skip_tls_verification=false must NOT reach the self-signed upstream; got %d, body: %s", secureCode, secureBody)
	require.GreaterOrEqual(t, secureCode, 500,
		"a TLS verification failure should surface as a 5xx from the proxy; got %d, body: %s", secureCode, secureBody)
}
