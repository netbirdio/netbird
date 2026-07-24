//go:build e2e

package agentnetwork

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// publishedPer1k carries the vendors' PUBLISHED per-1k-token USD rates for the
// models the live matrix can drive, keyed by the normalized model id the proxy
// stamps on the access-log row. These are intentionally hardcoded from the
// public price lists (not read from the proxy's pricing table) so the e2e run
// cross-checks the whole billing pipeline against an independent source: a
// wrong embedded rate, a broken model normalization, or a per-token-instead-of
// -per-1k-chunk regression (a 1000× blowup) all fail the assertion.
var publishedPer1k = map[string]struct{ in, out float64 }{
	"gpt-4o-mini":                 {0.00015, 0.0006}, // $0.15 / $0.60 per MTok
	"gpt-4o":                      {0.0025, 0.01},    // $2.50 / $10 per MTok
	"claude-haiku-4-5":            {0.001, 0.005},    // $1 / $5 per MTok
	"claude-sonnet-4-5":           {0.003, 0.015},    // $3 / $15 per MTok
	"claude-sonnet-4-6":           {0.003, 0.015},
	"kimi-k3":                     {0.003, 0.015},
	"anthropic.claude-haiku-4-5":  {0.001, 0.005}, // Bedrock mirrors first-party rates
	"anthropic.claude-sonnet-4-5": {0.003, 0.015},
	"anthropic.claude-sonnet-4-6": {0.003, 0.015},
}

// validateAccessLogCost recomputes the expected USD cost of a live access-log
// row from the published per-1k rates and asserts the stored cost_usd matches.
//
// Anthropic-shape providers report prompt-cache buckets ADDITIVELY: they are
// billed (read ≈0.1×, write ≈1.25× the input rate) and folded into
// total_tokens, but not into input_tokens/output_tokens — so when
// total > in + out the expectation widens to the [all-read, all-write] band
// for the extra tokens instead of failing on correct cache billing.
//
// Models the proxy deliberately does not price (gateway-prefixed ids like
// "openai/gpt-4o-mini") must store cost 0, never a guessed rate.
func validateAccessLogCost(t *testing.T, pc providerCase, row api.AgentNetworkAccessLog) {
	t.Helper()
	model := catalogModel(pc)
	rates, known := publishedPer1k[model]
	if !known {
		if strings.Contains(model, "/") {
			assert.Zerof(t, row.CostUsd,
				"gateway-prefixed model %q is not in the pricing table so the cost meter must skip (cost 0), got %v", model, row.CostUsd)
			return
		}
		t.Logf("no published rate on file for model %q (env-overridden?); skipping cost validation", model)
		return
	}

	require.Positive(t, row.InputTokens, "priced row must carry input tokens")
	require.Positive(t, row.OutputTokens, "priced row must carry output tokens")

	base := float64(row.InputTokens)/1000*rates.in + float64(row.OutputTokens)/1000*rates.out

	// Cache buckets ride total_tokens only (additive Anthropic/Bedrock shape).
	cacheTokens := row.TotalTokens - row.InputTokens - row.OutputTokens
	if cacheTokens < 0 {
		cacheTokens = 0
	}

	if cacheTokens == 0 {
		assert.InDeltaf(t, base, row.CostUsd, 1e-6,
			"cost for %s (%s): %d in × $%v/1k + %d out × $%v/1k must equal the stored cost",
			pc.name, model, row.InputTokens, rates.in, row.OutputTokens, rates.out)
		return
	}

	lo := base + float64(cacheTokens)/1000*rates.in*0.1  // whole bucket read from cache
	hi := base + float64(cacheTokens)/1000*rates.in*1.25 // whole bucket written to cache
	assert.GreaterOrEqualf(t, row.CostUsd, lo-1e-6,
		"cost for %s (%s) below the all-cache-read floor (base %v, %d cache tokens)", pc.name, model, base, cacheTokens)
	assert.LessOrEqualf(t, row.CostUsd, hi+1e-6,
		"cost for %s (%s) above the all-cache-write ceiling (base %v, %d cache tokens)", pc.name, model, base, cacheTokens)
}

// providerCase is one entry in the live provider matrix. The same scenario runs
// for every available provider; availability is keyed off env vars so the suite
// covers whatever credentials are present (source ~/.llm-keys locally / set the
// Actions secrets in CI).
type providerCase struct {
	name       string
	catalogID  string
	upstream   string
	apiKey     string
	model      string // body model (chat/messages) or path model@version (vertex)
	kind       string // harness.WireChat, harness.WireMessages, or harness.WireVertex
	project    string // vertex only: GCP project for the rawPredict path
	region     string // vertex only: GCP region for the rawPredict path
	pathPrefix string // base-URL path prefix the agent carries (e.g. "/anthropic" for Kimi)
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
		// Moonshot's Claude Code guide uses). The provider keeps the bare
		// default upstream and the AGENT carries the /anthropic prefix in
		// its base URL — exactly the documented Claude Code / Kimi CLI
		// setup (ANTHROPIC_BASE_URL=https://<endpoint>/anthropic) — so one
		// provider serves both shapes and the prefix rides through to
		// Moonshot. Run the Anthropic shape, the flagship Claude Code path;
		// the OpenAI wire shape is covered live by the other chat-shaped
		// matrix providers, and Kimi-over-chat passed with kimi-k3 before
		// the single-model constraint surfaced (run #73 on the kimi feature
		// branch). The platform serves this account exactly ONE model —
		// kimi-k3 (kimi-k2-thinking and even kimi-latest return
		// resource_not_found_error on both surfaces).
		ps = append(ps, providerCase{name: "kimi", catalogID: "kimi_api", upstream: "https://api.moonshot.ai", apiKey: k, model: "kimi-k3", kind: harness.WireMessages, pathPrefix: "/anthropic"})
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

	// Bedrock: path-routed, bearer auth. Model is the FULL cross-region
	// inference-profile id exactly as AWS issues it — region-family prefix
	// plus the date/version suffix. A bare or wrong-region id makes Bedrock
	// reject the request with "The provided model identifier is invalid"
	// before any inference runs. The proxy normalizes this id to the catalog
	// key (anthropic.claude-haiku-4-5) for routing/pricing/allowlists.
	// Defaults pair eu-central-1 with the eu.* profile; AWS_REGION overrides
	// the region and the prefix follows its family.
	if k := os.Getenv("AWS_BEARER_TOKEN_BEDROCK"); k != "" {
		region := os.Getenv("AWS_REGION")
		if region == "" {
			region = "eu-central-1"
		}
		// A valid Bedrock inference-profile id (region prefix + date + version),
		// overridable per account. `global.` profiles can be invoked from any
		// region; set AWS_BEDROCK_MODEL to match the enabled profile for the token.
		model := os.Getenv("AWS_BEDROCK_MODEL")
		if model == "" {
			model = "global.anthropic.claude-haiku-4-5-20251001-v1:0"
		}
		ps = append(ps, providerCase{name: "bedrock", catalogID: "bedrock_api", upstream: "https://bedrock-runtime." + region + ".amazonaws.com", apiKey: k, model: model, kind: harness.WireBedrock})
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
		// The router matches the normalized catalog id. Bedrock's request model
		// travels as a region-prefixed inference-profile id in the URL path
		// (us.anthropic...), which the router strips before matching, so register
		// the normalized form here or routing fails as model_not_routable.
		modelID := pc.model
		if pc.kind == harness.WireBedrock {
			modelID = catalogModel(pc)
		}
		req.Models = &[]api.AgentNetworkProviderModel{
			{Id: modelID, InputPer1k: 0.001, OutputPer1k: 0.002},
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
	// Probe first: the GET resolves the endpoint (DNS error fails) and its first packet wakes the lazy proxy peer, so WaitProxyPeer sees it connected; any HTTP status counts.
	proxyIP, err := cl.ResolveProxyIP(ctx, settings.Endpoint)
	require.NoError(t, err, "resolve agent-network endpoint to proxy IP")
	if err := cl.WaitProxyPeer(ctx, 180*time.Second); err != nil {
		t.Fatalf("client did not see the proxy peer: %v\n=== proxy logs ===\n%s", err, px.Logs(context.Background()))
	}

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
					c, b, cerr = cl.ChatPrefixed(ctx, settings.Endpoint, proxyIP, pc.pathPrefix, pc.kind, pc.model, "Reply with exactly: pong", sessionID)
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
			var row api.AgentNetworkAccessLog
			require.Eventually(t, func() bool {
				logs, lerr := srv.ListAccessLogs(ctx)
				if lerr != nil {
					return false
				}
				for _, r := range logs.Data {
					if r.SessionId != nil && *r.SessionId == sessionID {
						row = r
						return true
					}
				}
				return false
			}, 30*time.Second, 2*time.Second, "session id %q must be recorded in an access-log row for %s", sessionID, pc.name)

			// The stored cost must match the vendor's published per-1k rates
			// applied to the row's token counts (cache-aware for the additive
			// Anthropic/Bedrock buckets, zero for unpriced gateway model ids).
			validateAccessLogCost(t, pc, row)
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
