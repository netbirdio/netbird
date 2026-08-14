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
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// per1k is a model's published USD rates per 1k tokens. read is the prompt-cache read rate
// (OpenAI: the cached-input discount rate); write is the cache-creation rate where one exists.
type per1k struct{ in, out, read, write float64 }

// publishedPer1k hardcodes the vendors' PUBLISHED rates for the models the live matrix can drive,
// keyed by the normalized model id the proxy stamps. Deliberately independent of NetBird's own
// default pricing table so a wrong default rate or a broken normalization fails the run.
//
// These rates are also what providerRequest registers as the operator's per-model prices. Since
// management now ships operator prices to the cost meter as a per-provider-record table that is
// consulted BEFORE the surface defaults, registering the published rate is what keeps this matrix
// asserting vendor rates — and exercises the per-record path at the same time.
var publishedPer1k = map[string]per1k{
	"gpt-4o-mini":                 {0.00015, 0.0006, 0.000075, 0},
	"gpt-4o":                      {0.0025, 0.01, 0.00125, 0},
	"claude-haiku-4-5":            {0.001, 0.005, 0.0001, 0.00125},
	"claude-sonnet-4-5":           {0.003, 0.015, 0.0003, 0.00375},
	"claude-sonnet-4-6":           {0.003, 0.015, 0.0003, 0.00375},
	"kimi-k3":                     {0.003, 0.015, 0.0003, 0.003}, // no published write rate: bills at the input rate
	"anthropic.claude-haiku-4-5":  {0.001, 0.005, 0.0001, 0.00125},
	"anthropic.claude-sonnet-4-5": {0.003, 0.015, 0.0003, 0.00375},
	"anthropic.claude-sonnet-4-6": {0.003, 0.015, 0.0003, 0.00375},
	// Gateway-prefixed ids (Vercel AI Gateway, OpenRouter). A gateway model is not in
	// NetBird's default table, so before operator pricing it could only be recorded at
	// cost 0. The operator names it and prices it — at the underlying vendor's published
	// rate, which is what the gateway charges through — so these rows are now priced.
	"openai/gpt-4o-mini": {0.00015, 0.0006, 0.000075, 0},
	"openai/gpt-4o":      {0.0025, 0.01, 0.00125, 0},
}

// rawCostVerificationSQL is the operator-facing double-check, run straight against the management
// sqlite store: recompute each usage row's expected total and cache cost from its own persisted
// token buckets and hardcoded published rates. OpenAI counts cached tokens as a subset of input;
// Anthropic-shape providers count cache buckets additively.
//
// The rate rows must stay in sync with publishedPer1k — they are the same vendor rates the matrix
// registers as operator prices. The join is on model, so rows written by other tests in this
// package (which price their own made-up model ids) are simply not covered here.
const rawCostVerificationSQL = `
WITH rates(model, in_rate, out_rate, read_rate, write_rate) AS (
  VALUES
    ('gpt-4o-mini',                 0.00015, 0.0006, 0.000075, 0.0),
    ('gpt-4o',                      0.0025,  0.01,   0.00125,  0.0),
    ('claude-haiku-4-5',            0.001,   0.005,  0.0001,   0.00125),
    ('claude-sonnet-4-5',           0.003,   0.015,  0.0003,   0.00375),
    ('claude-sonnet-4-6',           0.003,   0.015,  0.0003,   0.00375),
    ('kimi-k3',                     0.003,   0.015,  0.0003,   0.003),
    ('anthropic.claude-haiku-4-5',  0.001,   0.005,  0.0001,   0.00125),
    ('anthropic.claude-sonnet-4-5', 0.003,   0.015,  0.0003,   0.00375),
    ('anthropic.claude-sonnet-4-6', 0.003,   0.015,  0.0003,   0.00375),
    ('openai/gpt-4o-mini',          0.00015, 0.0006, 0.000075, 0.0),
    ('openai/gpt-4o',               0.0025,  0.01,   0.00125,  0.0)
)
SELECT
  u.provider,
  u.model,
  u.input_tokens,
  u.output_tokens,
  u.cached_input_tokens,
  u.cache_creation_tokens,
  u.input_cost_usd,
  u.cached_input_cost_usd,
  u.cache_creation_cost_usd,
  u.output_cost_usd,
  -- No cost_usd / cache_cost_usd columns are stored: both are derived from the
  -- four per-bucket columns above, exactly as the API renders them.
  (u.input_cost_usd + u.cached_input_cost_usd + u.cache_creation_cost_usd + u.output_cost_usd) AS cost_usd,
  (u.cached_input_cost_usd + u.cache_creation_cost_usd) AS cache_cost_usd,
  CASE WHEN u.provider = 'openai' THEN
    (u.input_tokens - MIN(u.cached_input_tokens, u.input_tokens))*r.in_rate/1000.0
  ELSE
    u.input_tokens*r.in_rate/1000.0
  END AS expected_input,
  CASE WHEN u.provider = 'openai' THEN
    MIN(u.cached_input_tokens, u.input_tokens)*r.read_rate/1000.0
  ELSE
    u.cached_input_tokens*r.read_rate/1000.0
  END AS expected_cached_input,
  CASE WHEN u.provider = 'openai' THEN
    0.0
  ELSE
    u.cache_creation_tokens*r.write_rate/1000.0
  END AS expected_cache_creation,
  u.output_tokens*r.out_rate/1000.0 AS expected_output,
  CASE WHEN u.provider = 'openai' THEN
    (u.input_tokens - MIN(u.cached_input_tokens, u.input_tokens))*r.in_rate/1000.0
      + MIN(u.cached_input_tokens, u.input_tokens)*r.read_rate/1000.0
      + u.output_tokens*r.out_rate/1000.0
  ELSE
    u.input_tokens*r.in_rate/1000.0 + u.cached_input_tokens*r.read_rate/1000.0
      + u.cache_creation_tokens*r.write_rate/1000.0 + u.output_tokens*r.out_rate/1000.0
  END AS expected_total,
  CASE WHEN u.provider = 'openai' THEN
    MIN(u.cached_input_tokens, u.input_tokens)*r.read_rate/1000.0
  ELSE
    u.cached_input_tokens*r.read_rate/1000.0 + u.cache_creation_tokens*r.write_rate/1000.0
  END AS expected_cache
FROM agent_network_request_usage u
JOIN rates r ON r.model = u.model
ORDER BY u.timestamp`

// verifyUsageRowsSQL re-checks every persisted usage row directly in the management sqlite store,
// bypassing the API path — the same audit an operator can run on a production store.db.
func verifyUsageRowsSQL(t *testing.T, srv *harness.Combined) {
	t.Helper()

	dbPath, err := srv.SnapshotStoreDB(t.TempDir())
	require.NoError(t, err, "snapshot management sqlite store")

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	require.NoError(t, err, "open store snapshot")
	sqlDB, err := db.DB()
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()

	rows, err := db.Raw(rawCostVerificationSQL).Rows()
	require.NoError(t, err, "run raw cost verification query")
	defer func() { _ = rows.Close() }()

	verified := 0
	for rows.Next() {
		var provider, model string
		var inTok, outTok, readTok, writeTok int64
		var inCost, cachedInCost, cacheCreateCost, outCost, cost, cacheCost float64
		var wantInput, wantCachedInput, wantCacheCreation, wantOutput, wantTotal, wantCache float64
		require.NoError(t, rows.Scan(&provider, &model, &inTok, &outTok, &readTok, &writeTok,
			&inCost, &cachedInCost, &cacheCreateCost, &outCost, &cost, &cacheCost,
			&wantInput, &wantCachedInput, &wantCacheCreation, &wantOutput, &wantTotal, &wantCache), "scan usage row")
		t.Logf("[sql] %s/%s: in=%d out=%d cache_read=%d cache_write=%d stored in/cached/create/out=$%.6f/$%.6f/$%.6f/$%.6f total=$%.6f cache=$%.6f expected total=$%.6f cache=$%.6f",
			provider, model, inTok, outTok, readTok, writeTok,
			inCost, cachedInCost, cacheCreateCost, outCost, cost, cacheCost, wantTotal, wantCache)
		assert.InDeltaf(t, wantInput, inCost, 1e-6, "stored input_cost_usd for %s/%s must match the published-rate recompute", provider, model)
		assert.InDeltaf(t, wantCachedInput, cachedInCost, 1e-6, "stored cached_input_cost_usd for %s/%s must match the published-rate recompute", provider, model)
		assert.InDeltaf(t, wantCacheCreation, cacheCreateCost, 1e-6, "stored cache_creation_cost_usd for %s/%s must match the published-rate recompute", provider, model)
		assert.InDeltaf(t, wantOutput, outCost, 1e-6, "stored output_cost_usd for %s/%s must match the published-rate recompute", provider, model)
		assert.InDeltaf(t, wantTotal, cost, 1e-6, "derived cost_usd for %s/%s must match the published-rate recompute", provider, model)
		assert.InDeltaf(t, wantCache, cacheCost, 1e-6, "derived cache_cost_usd for %s/%s must match the published-rate recompute", provider, model)
		assert.InDeltaf(t, inCost+cachedInCost+cacheCreateCost+outCost, cost, 1e-9,
			"stored buckets must sum to the derived cost_usd for %s/%s", provider, model)
		verified++
	}
	require.NoError(t, rows.Err(), "iterate usage rows")
	require.Positive(t, verified, "raw SQL check must cover at least one usage row")
	t.Logf("[sql] verified %d usage rows in store.db against published rates", verified)

	// Gateway-prefixed model ids are absent from NetBird's default pricing table, so they are
	// priced only because the operator registered and priced them on the provider record. Assert
	// they are priced (not silently 0) — the join above already checked the exact figures for the
	// ones this matrix drives. A gateway row at cost 0 means the per-record table never reached
	// the cost meter, which is the regression this guards.
	gwRows, err := db.Raw(`SELECT model,
	  (input_cost_usd + cached_input_cost_usd + cache_creation_cost_usd + output_cost_usd) AS cost_usd
	  FROM agent_network_request_usage WHERE model LIKE '%/%'`).Rows()
	require.NoError(t, err, "query gateway-prefixed usage rows")
	defer func() { _ = gwRows.Close() }()
	for gwRows.Next() {
		var model string
		var cost float64
		require.NoError(t, gwRows.Scan(&model, &cost), "scan gateway usage row")
		t.Logf("[sql] gateway %s: stored=$%.6f (priced from the operator's per-record rate)", model, cost)
		assert.Positivef(t, cost, "gateway-prefixed model %q is priced on the provider record, so its cost must be > 0", model)
	}
	require.NoError(t, gwRows.Err(), "iterate gateway usage rows")
}

// validateAccessLogCost recomputes a live access-log row's expected total and cache cost from the
// published per-1k rates and the row's persisted token buckets, and asserts both stored values.
// Gateway-prefixed model ids the proxy deliberately does not price must store cost 0.
func validateAccessLogCost(t *testing.T, pc providerCase, row api.AgentNetworkAccessLog) {
	t.Helper()
	model := catalogModel(pc)
	provider := ""
	if row.Provider != nil {
		provider = *row.Provider
	}
	t.Logf("[cost] %s: provider=%s model=%s in=%d out=%d total=%d cache_read=%d cache_write=%d cost=$%.6f cache_cost=$%.6f",
		pc.name, provider, model, row.InputTokens, row.OutputTokens, row.TotalTokens,
		row.CachedInputTokens, row.CacheCreationTokens, row.CostUsd, row.CacheCostUsd)

	rates, known := publishedPer1k[model]
	if !known {
		t.Logf("[cost] %s: no published rate on file for model %q (env-overridden?); skipping cost validation", pc.name, model)
		return
	}

	// input_tokens may legitimately be 0: Moonshot/Kimi reports fully cached prompts under the cache
	// buckets only. Output and total must always be present on a priced row.
	require.Positive(t, row.OutputTokens, "priced row must carry output tokens")
	require.Positive(t, row.TotalTokens, "priced row must carry total tokens")

	var wantInput, wantCachedInput, wantCacheCreation float64
	if provider == "openai" {
		cached := min(row.CachedInputTokens, row.InputTokens) // cached is a subset of input
		wantInput = float64(row.InputTokens-cached) / 1000 * rates.in
		wantCachedInput = float64(cached) / 1000 * rates.read
		// OpenAI has no cache-write bucket; wantCacheCreation stays 0.
	} else {
		// Anthropic / Bedrock shape: cache buckets are additive to input_tokens.
		wantInput = float64(row.InputTokens) / 1000 * rates.in
		wantCachedInput = float64(row.CachedInputTokens) / 1000 * rates.read
		wantCacheCreation = float64(row.CacheCreationTokens) / 1000 * rates.write
	}
	wantOutput := float64(row.OutputTokens) / 1000 * rates.out
	wantCache := wantCachedInput + wantCacheCreation
	wantTotal := wantInput + wantCache + wantOutput

	t.Logf("[cost] %s: expecting input=$%.6f cached_input=$%.6f cache_creation=$%.6f output=$%.6f total=$%.6f cache=$%.6f from published rates",
		pc.name, wantInput, wantCachedInput, wantCacheCreation, wantOutput, wantTotal, wantCache)
	assert.InDeltaf(t, wantInput, row.InputCostUsd, 1e-6, "stored input_cost_usd for %s (%s)", pc.name, model)
	assert.InDeltaf(t, wantCachedInput, row.CachedInputCostUsd, 1e-6, "stored cached_input_cost_usd for %s (%s)", pc.name, model)
	assert.InDeltaf(t, wantCacheCreation, row.CacheCreationCostUsd, 1e-6, "stored cache_creation_cost_usd for %s (%s)", pc.name, model)
	assert.InDeltaf(t, wantOutput, row.OutputCostUsd, 1e-6, "stored output_cost_usd for %s (%s)", pc.name, model)
	assert.InDeltaf(t, wantTotal, row.CostUsd, 1e-6, "derived cost_usd for %s (%s)", pc.name, model)
	assert.InDeltaf(t, wantCache, row.CacheCostUsd, 1e-6, "derived cache_cost_usd for %s (%s)", pc.name, model)

	// The aggregates must be exactly the sum of the stored components, not an
	// independently-computed figure that could drift from the breakdown.
	assert.InDeltaf(t, row.InputCostUsd+row.CachedInputCostUsd+row.CacheCreationCostUsd+row.OutputCostUsd,
		row.CostUsd, 1e-9, "stored buckets must sum to the derived cost_usd for %s (%s)", pc.name, model)
	assert.InDeltaf(t, row.CachedInputCostUsd+row.CacheCreationCostUsd,
		row.CacheCostUsd, 1e-9, "stored cache buckets must sum to the derived cache_cost_usd for %s (%s)", pc.name, model)
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
		// A valid Bedrock inference-profile id, overridable per account (AWS_BEDROCK_MODEL, also the
		// workflow's bedrock_model dispatch input). `global.` profiles work from any region. Defaults to
		// Sonnet 4.6, whose id convention dropped the -YYYYMMDD-v1:0 suffix that Haiku 4.5 still carries.
		model := os.Getenv("AWS_BEDROCK_MODEL")
		if model == "" {
			model = "global.anthropic.claude-sonnet-4-6"
		}
		ps = append(ps, providerCase{name: "bedrock", catalogID: "bedrock_api", upstream: "https://bedrock-runtime." + region + ".amazonaws.com", apiKey: k, model: model, kind: harness.WireBedrock})
	}
	return ps
}

// providerRequest builds a create request for a matrix provider: enabled, with
// its model registered at the vendor's published rates for body-routed
// providers, and no models for the path-routed Vertex (whose model lives in the
// request path, so it prices from the defaults table management ships).
//
// The registered rates matter: management synthesizes them into the cost
// meter's per-provider-record table, which is consulted before the surface
// defaults, so these are the rates the proxy actually bills with. Registering
// the published rate keeps the cost assertions vendor-anchored while covering
// the operator-pricing path. A model with no published rate on file (an
// env-overridden Bedrock profile) falls back to a nominal rate, and
// validateAccessLogCost skips its cost check.
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
		model := api.AgentNetworkProviderModel{Id: modelID, InputPer1k: 0.001, OutputPer1k: 0.002}
		if rates, known := publishedPer1k[catalogModel(pc)]; known {
			model.InputPer1k = rates.in
			model.OutputPer1k = rates.out
			// Pin the cache rates too, rather than letting them inherit from the
			// defaults table: a gateway-prefixed id has no default entry to
			// inherit from, and an unset rate bills that bucket at the input
			// rate, which would not match the published-rate recompute.
			if rates.read > 0 {
				model.CachedInputPer1k = ptr(rates.read) // OpenAI shape
				model.CacheReadPer1k = ptr(rates.read)   // Anthropic / Bedrock shape
			}
			if rates.write > 0 {
				model.CacheCreationPer1k = ptr(rates.write)
			}
		}
		req.Models = &[]api.AgentNetworkProviderModel{model}
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
	// proxy, so we enable everything up front).
	ids := make([]string, 0, len(matrix))
	for _, pc := range matrix {
		req := providerRequest(pc)
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

			// A long-form prompt so completions carry realistic token counts for cost validation;
			// max_tokens in the harness bodies (2048) lets the full answer through.
			const matrixPrompt = "explain GitHub workflow in 1000 words"

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
					c, b, cerr = cl.Vertex(ctx, settings.Endpoint, proxyIP, pc.project, pc.region, pc.model, matrixPrompt, sessionID)
				case harness.WireBedrock:
					c, b, cerr = cl.Bedrock(ctx, settings.Endpoint, proxyIP, pc.model, matrixPrompt, sessionID)
				default:
					c, b, cerr = cl.ChatPrefixed(ctx, settings.Endpoint, proxyIP, pc.pathPrefix, pc.kind, pc.model, matrixPrompt, sessionID)
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

			// Stored total and cache cost must match the published rates applied to the row's buckets.
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

	// Final raw-SQL audit: bypass the API and re-verify every persisted usage row in the store.
	verifyUsageRowsSQL(t, srv)
}
