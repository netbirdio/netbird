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
	model     string // body model (chat/messages) or path model@version (vertex)
	kind      string // harness.WireChat, harness.WireMessages, or harness.WireVertex
	project   string // vertex only: GCP project for the rawPredict path
	region    string // vertex only: GCP region for the rawPredict path
}

// availableProviders builds the matrix from the provider env vars that are set.
func availableProviders() []providerCase {
	var ps []providerCase
	if k := os.Getenv("OPENAI_TOKEN"); k != "" {
		ps = append(ps, providerCase{name: "openai", catalogID: "openai_api", upstream: "https://api.openai.com", apiKey: k, model: "gpt-4o-mini", kind: harness.WireChat})
	}
	if k := os.Getenv("ANTHROPIC_TOKEN"); k != "" {
		ps = append(ps, providerCase{name: "anthropic", catalogID: "anthropic_api", upstream: "https://api.anthropic.com", apiKey: k, model: "claude-haiku-4-5", kind: harness.WireMessages})
	}
	if k := os.Getenv("KIMI_TOKEN"); k != "" {
		// Kimi (Moonshot AI) serves two body shapes from the same key: OpenAI
		// Chat Completions on the bare host (/v1/...) and the Anthropic
		// Messages API under the /anthropic path prefix (the endpoint
		// Moonshot's Claude Code guide uses). One provider record per shape,
		// with distinct model strings so model→provider routing stays
		// unambiguous while both are enabled.
		ps = append(ps, providerCase{name: "kimi-openai", catalogID: "kimi_api", upstream: "https://api.moonshot.ai", apiKey: k, model: "kimi-k3", kind: harness.WireChat})
		ps = append(ps, providerCase{name: "kimi-anthropic", catalogID: "kimi_api", upstream: "https://api.moonshot.ai/anthropic", apiKey: k, model: "kimi-k2-thinking", kind: harness.WireMessages})
	}
	if k, u := os.Getenv("VERCEL_TOKEN"), os.Getenv("VERCEL_URL"); k != "" && u != "" {
		ps = append(ps, providerCase{name: "vercel", catalogID: "vercel_ai_gateway", upstream: u, apiKey: k, model: "openai/gpt-4o-mini", kind: harness.WireChat})
	}
	if k, u := os.Getenv("OPENROUTER_TOKEN"), os.Getenv("OPENROUTER_URL"); k != "" && u != "" {
		// Distinct model string from Vercel so each provider routes unambiguously
		// while all are enabled together.
		ps = append(ps, providerCase{name: "openrouter", catalogID: "openrouter", upstream: u, apiKey: k, model: "openai/gpt-4o", kind: harness.WireChat})
	}
	if k, u := os.Getenv("CLOUDFLARE_TOKEN"), os.Getenv("CLOUDFLARE_URL"); k != "" && u != "" {
		// Cloudflare AI Gateway routes by a provider segment in the URL path;
		// append the openai provider unless the gateway URL already carries one.
		if !strings.Contains(u, "/openai") {
			u = strings.TrimRight(u, "/") + "/openai"
		}
		// Raw model (distinct string from OpenAI's gpt-4o-mini).
		ps = append(ps, providerCase{name: "cloudflare", catalogID: "cloudflare_ai_gateway", upstream: u, apiKey: k, model: "gpt-4o", kind: harness.WireChat})
	}
	// Vertex (vertex_ai_api): Anthropic-on-Vertex, path-routed, SA-OAuth
	// (api_key = keyfile::<SA>). The model travels in the rawPredict path rather
	// than the body, so the provider is created without a models array. Region
	// defaults to "global" (host aiplatform.googleapis.com); a real region uses
	// <region>-aiplatform.googleapis.com.
	if sa := os.Getenv("GOOGLE_VERTEX_SA_BASE64"); sa != "" {
		project := os.Getenv("GOOGLE_VERTEX_PROJECT")
		if project != "" {
			region := os.Getenv("GOOGLE_VERTEX_REGION")
			if region == "" {
				region = "global"
			}
			host := "aiplatform.googleapis.com"
			if region != "global" {
				host = region + "-aiplatform.googleapis.com"
			}
			model := os.Getenv("GOOGLE_VERTEX_MODEL")
			if model == "" {
				model = "claude-sonnet-4-5@20250929"
			}
			ps = append(ps, providerCase{
				name: "vertex", catalogID: "vertex_ai_api", upstream: "https://" + host,
				apiKey: "keyfile::" + sa, model: model, kind: harness.WireVertex,
				project: project, region: region,
			})
		}
	}

	// Bedrock: path-routed, bearer auth. Model is a cross-region inference
	// profile id (distinct string from the first-party Anthropic case).
	if k := os.Getenv("AWS_BEARER_TOKEN_BEDROCK"); k != "" {
		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = "us-east-1"
		}
		ps = append(ps, providerCase{name: "bedrock", catalogID: "bedrock_api", upstream: "https://bedrock-runtime." + region + ".amazonaws.com", apiKey: k, model: "us.anthropic.claude-haiku-4-5", kind: harness.WireBedrock})
	}
	return ps
}

// providerRequest builds a create request for a matrix provider: enabled, with
// a uniquely-priced model for body-routed providers and none for the
// path-routed Vertex (whose model lives in the request path).
func providerRequest(pc providerCase) api.AgentNetworkProviderRequest {
	req := api.AgentNetworkProviderRequest{
		Name:        pc.name,
		ProviderId:  pc.catalogID,
		UpstreamUrl: pc.upstream,
		ApiKey:      &pc.apiKey,
		Enabled:     ptr(true),
	}
	if pc.kind != harness.WireVertex {
		req.Models = &[]api.AgentNetworkProviderModel{
			{Id: pc.model, InputPer1k: 0.001, OutputPer1k: 0.002},
		}
	}
	return req
}

// TestProvidersMatrix is Pillar 3: it provisions every available provider (all
// enabled, each with a unique model so routing stays unambiguous), runs proxy +
// client once, and drives the same live chat-completion scenario through each
// provider over the WireGuard tunnel. Each provider must return 200 and produce
// an ingested access-log row.
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
		req := providerRequest(pc)
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
		// Token limit at the 60s window floor with caps far above the few hundred
		// tokens this suite drives, so it never blocks traffic but switches on
		// usage metering, which is what makes consumption rows get recorded.
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

			// Unique per provider so we can find this provider's row by its
			// session id and confirm the marker propagated end-to-end.
			sessionID := "e2e-session-" + pc.name

			// Retry briefly to absorb tunnel/DNS jitter on the first call.
			var code int
			var body string
			deadline := time.Now().Add(90 * time.Second)
			for time.Now().Before(deadline) {
				var c int
				var b string
				var cerr error
				switch pc.kind {
				case harness.WireVertex:
					c, b, cerr = cl.Vertex(ctx, settings.Endpoint, proxyIP, pc.project, pc.region, pc.model, "Reply with exactly: pong", sessionID)
				case harness.WireBedrock:
					c, b, cerr = cl.Bedrock(ctx, settings.Endpoint, proxyIP, pc.model, "Reply with exactly: pong", sessionID)
				default:
					c, b, cerr = cl.Chat(ctx, settings.Endpoint, proxyIP, pc.kind, pc.model, "Reply with exactly: pong", sessionID)
				}
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

			// The session id sent as x-session-id must round-trip into the
			// access-log row for this provider.
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
			}, 30*time.Second, 2*time.Second, "session id %q must be recorded in an access-log row for %s", sessionID, pc.name)
		})
	}

	// Metering: the policy's uncapped token limit switches on usage recording,
	// so the live traffic just driven must surface as consumption rows with
	// positive token counts. Consumption is account-scoped (keyed by source
	// group / user and time window, not per provider), and ingest is async, so
	// poll for any row that has booked tokens.
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
	}, 60*time.Second, 3*time.Second, "consumption must be recorded with positive token counts after live traffic")
}
