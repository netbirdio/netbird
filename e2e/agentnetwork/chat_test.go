//go:build e2e

package agentnetwork

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// providerCase is one entry in the live provider matrix. The same scenario runs
// for every available provider; availability is keyed off env vars so the suite
// covers whatever credentials are present (source ~/.llm-keys locally / set the
// Actions secrets in CI).
type providerCase struct {
	name      string
	catalogID string
	upstream  string
	apiKey    string
	model     string
	kind      string // harness.WireChat or harness.WireMessages
}

// availableProviders builds the matrix from the provider env vars that are set.
func availableProviders() []providerCase {
	var ps []providerCase
	if k := os.Getenv("OPENAI_TOKEN"); k != "" {
		ps = append(ps, providerCase{"openai", "openai_api", "https://api.openai.com", k, "gpt-4o-mini", harness.WireChat})
	}
	if k := os.Getenv("ANTHROPIC_TOKEN"); k != "" {
		ps = append(ps, providerCase{"anthropic", "anthropic_api", "https://api.anthropic.com", k, "claude-haiku-4-5", harness.WireMessages})
	}
	if k, u := os.Getenv("VERCEL_TOKEN"), os.Getenv("VERCEL_URL"); k != "" && u != "" {
		ps = append(ps, providerCase{"vercel", "vercel_ai_gateway", u, k, "openai/gpt-4o-mini", harness.WireChat})
	}
	if k, u := os.Getenv("OPENROUTER_TOKEN"), os.Getenv("OPENROUTER_URL"); k != "" && u != "" {
		// Distinct model string from Vercel so each provider routes unambiguously
		// while all are enabled together.
		ps = append(ps, providerCase{"openrouter", "openrouter", u, k, "openai/gpt-4o", harness.WireChat})
	}
	if k, u := os.Getenv("CLOUDFLARE_TOKEN"), os.Getenv("CLOUDFLARE_URL"); k != "" && u != "" {
		// Cloudflare AI Gateway routes by a provider segment in the URL path;
		// append the openai provider unless the gateway URL already carries one.
		if !strings.Contains(u, "/openai") {
			u = strings.TrimRight(u, "/") + "/openai"
		}
		// Raw model (distinct string from OpenAI's gpt-4o-mini).
		ps = append(ps, providerCase{"cloudflare", "cloudflare_ai_gateway", u, k, "gpt-4o", harness.WireChat})
	}
	// Vertex (vertex_ai_api) is intentionally NOT in this uniform matrix: it is
	// driven by a bespoke Vertex rawPredict path
	// (/v1/projects/<project>/locations/<region>/publishers/anthropic/models/<model>:rawPredict)
	// with a Vertex-specific body, not the shared chat/messages shapes. It needs
	// a dedicated scenario; see the bash agent-network-full vertex recipe.

	// Bedrock: path-routed, bearer auth. Model is a cross-region inference
	// profile id (distinct string from the first-party Anthropic case).
	if k := os.Getenv("AWS_BEARER_TOKEN_BEDROCK"); k != "" {
		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = "us-east-1"
		}
		ps = append(ps, providerCase{"bedrock", "bedrock_api", "https://bedrock-runtime." + region + ".amazonaws.com", k, "us.anthropic.claude-haiku-4-5", harness.WireMessages})
	}
	return ps
}

// TestProvidersMatrix is Pillar 3: it provisions every available provider, runs
// proxy + client once, and drives the same live chat-completion scenario
// through each provider over the WireGuard tunnel — exactly one provider enabled
// at a time so model→provider routing is unambiguous. Each provider must return
// 200 and produce an ingested access-log row.
func TestProvidersMatrix(t *testing.T) {
	matrix := availableProviders()
	if len(matrix) == 0 {
		t.Skip("no provider keys set; source ~/.llm-keys to run the provider matrix")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	// Group + setup key the client joins into; the policy authorizes it.
	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-agents"})
	require.NoError(t, err, "create agents group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")
	require.NotEmpty(t, sk.Key, "setup key plaintext")

	// Create every provider, all enabled, each with a unique model string so the
	// proxy's connect-time snapshot carries them all and model→provider routing
	// is unambiguous (provider toggles after connect don't reconcile to the
	// proxy, so we enable everything up front). The first create bootstraps the
	// cluster.
	ids := make([]string, 0, len(matrix))
	for i, pc := range matrix {
		req := api.AgentNetworkProviderRequest{
			Name:        pc.name,
			ProviderId:  pc.catalogID,
			UpstreamUrl: pc.upstream,
			ApiKey:      &pc.apiKey,
			Enabled:     ptr(true),
			Models: &[]api.AgentNetworkProviderModel{
				{Id: pc.model, InputPer1k: 0.001, OutputPer1k: 0.002},
			},
		}
		if i == 0 {
			req.BootstrapCluster = ptr(harness.AgentNetworkCluster)
		}
		prov, perr := srv.CreateProvider(ctx, req)
		require.NoError(t, perr, "create provider %s", pc.name)
		ids = append(ids, prov.Id)
		id := prov.Id
		t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), id) })
	}

	enabled := true
	pol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-allow",
		Enabled:                &enabled,
		SourceGroups:           []string{grp.Id},
		DestinationProviderIds: ids,
	})
	require.NoError(t, err, "create policy")
	t.Cleanup(func() { _ = srv.DeletePolicy(context.Background(), pol.Id) })

	settings, err := srv.GetSettings(ctx)
	require.NoError(t, err, "read settings for endpoint")
	require.NotEmpty(t, settings.Endpoint, "agent-network endpoint must be assigned")

	// Proxy (global CLI token) + client, brought up once.
	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-proxy")
	require.NoError(t, err, "mint proxy token via CLI")
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
	require.NoError(t, err, "resolve agent-network endpoint to proxy IP")

	for _, pc := range matrix {
		pc := pc
		t.Run(pc.name, func(t *testing.T) {
			before, _ := srv.ListAccessLogs(ctx)

			// Retry briefly to absorb tunnel/DNS jitter on the first call.
			var code int
			var body string
			deadline := time.Now().Add(90 * time.Second)
			for time.Now().Before(deadline) {
				c, b, cerr := cl.Chat(ctx, settings.Endpoint, proxyIP, pc.kind, pc.model, "Reply with exactly: pong")
				if cerr == nil {
					code, body = c, b
					if code == 200 {
						break
					}
				}
				time.Sleep(5 * time.Second)
			}
			require.Equal(t, 200, code, "chat through %s (%s %s) should return 200; body: %s", pc.name, pc.kind, pc.model, body)

			require.Eventually(t, func() bool {
				logs, lerr := srv.ListAccessLogs(ctx)
				return lerr == nil && logs.TotalRecords > before.TotalRecords
			}, 30*time.Second, 2*time.Second, "an access-log row should be ingested for %s", pc.name)
		})
	}
}
