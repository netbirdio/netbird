//go:build e2e

package agentnetwork

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/netbirdio/netbird/e2e/harness"
	"github.com/netbirdio/netbird/shared/management/http/api"
)

// The mock vLLM upstream (harness/vllm.go) always answers with this fixed usage
// block, so every request drives deterministic token counts regardless of the
// model the client asks for. The proxy prices off the REQUEST model, not the
// upstream response model, so a made-up model id billed at operator rates lets
// these tests assert exact costs without a real vendor key.
const (
	vllmPromptTokens     = 11
	vllmCompletionTokens = 2
)

// pricedEnv is a connected single-provider agent-network deployment pointed at
// the mock vLLM upstream, with the proxy and client up and the endpoint resolved
// — ready to drive chat. All containers are torn down via t.Cleanup.
type pricedEnv struct {
	provID   string
	upstream string // provider upstream URL, needed to re-send on a PUT update
	endpoint string
	proxyIP  string
	client   *harness.Client
	proxy    *harness.Proxy
}

// provisionPricedProvider brings up the full path for a cost test: a mock vLLM
// upstream, a group + reusable setup key, one openai_api provider pointed at the
// mock enumerating exactly the given models (with the operator's per-1k prices),
// a policy whose token limit switches on usage metering, and a connected proxy +
// client. The provider is created with the given models so the router dispatches
// them to this provider and the cost meter bills at these rates.
//
// Passing nil models makes it a gateway-style catch-all: the router claims every
// model, and since the synthesizer ships no per-provider-record pricing entry
// for a provider that enumerates nothing, the shipped defaults table is the only
// thing that can price the request. The policy sets no model guardrail, so the
// proxy's per-provider allowlist backstop stays empty and any model routes.
func provisionPricedProvider(t *testing.T, ctx context.Context, name string, models []api.AgentNetworkProviderModel) pricedEnv {
	t.Helper()

	vllm, err := harness.StartVLLM(ctx, srv)
	require.NoError(t, err, "start mock vLLM upstream")
	t.Cleanup(func() { _ = vllm.Terminate(context.Background()) })

	grp, err := srv.API().Groups.Create(ctx, api.PostApiGroupsJSONRequestBody{Name: "e2e-price-" + name})
	require.NoError(t, err, "create group")
	t.Cleanup(func() { _ = srv.API().Groups.Delete(context.Background(), grp.Id) })

	ephemeral := false
	sk, err := srv.API().SetupKeys.Create(ctx, api.PostApiSetupKeysJSONRequestBody{
		Name:       "e2e-price-" + name + "-client",
		Type:       "reusable",
		ExpiresIn:  86400,
		UsageLimit: 0,
		AutoGroups: []string{grp.Id},
		Ephemeral:  &ephemeral,
	})
	require.NoError(t, err, "mint setup key")
	require.NotEmpty(t, sk.Key, "setup key plaintext")

	// The mock ignores auth, so a dummy key satisfies the "Bearer ${API_KEY}"
	// template. openai_api is a known catalog provider; the enumerated model id
	// need NOT be in the catalog — the operator names it and prices it here.
	dummyKey := "sk-price-e2e"
	prov, err := srv.CreateProvider(ctx, api.AgentNetworkProviderRequest{
		Name:             name,
		ProviderId:       "openai_api",
		UpstreamUrl:      vllm.URL,
		ApiKey:           &dummyKey,
		Enabled:          ptr(true),
		BootstrapCluster: ptr(harness.AgentNetworkCluster),
		Models:           &models,
	})
	require.NoError(t, err, "create provider")
	t.Cleanup(func() { _ = srv.DeleteProvider(context.Background(), prov.Id) })

	// Uncapped token limit: never blocks the handful of tokens driven here, but
	// switches on usage metering — the switch that makes consumption rows record.
	enabled := true
	pol, err := srv.CreatePolicy(ctx, api.AgentNetworkPolicyRequest{
		Name:                   "e2e-price-" + name,
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

	proxyToken, err := srv.CreateProxyTokenCLI(ctx, "e2e-price-"+name+"-proxy")
	require.NoError(t, err, "mint proxy token")
	px, err := harness.StartProxy(ctx, srv, proxyToken)
	require.NoError(t, err, "start proxy")
	t.Cleanup(func() { _ = px.Terminate(context.Background()) })

	cl, err := harness.StartClient(ctx, srv, sk.Key)
	require.NoError(t, err, "start client")
	t.Cleanup(func() { _ = cl.Terminate(context.Background()) })

	require.NoError(t, cl.WaitConnected(ctx, 90*time.Second), "client must connect to management")
	// Probe first: the GET resolves the endpoint and its first packet wakes the
	// lazy proxy peer, so WaitProxyPeer then observes it connected.
	proxyIP, err := cl.ResolveProxyIP(ctx, settings.Endpoint)
	require.NoError(t, err, "resolve endpoint to proxy IP")
	if err := cl.WaitProxyPeer(ctx, 180*time.Second); err != nil {
		t.Fatalf("client did not see the proxy peer: %v\n=== proxy logs ===\n%s", err, px.Logs(context.Background()))
	}

	return pricedEnv{provID: prov.Id, upstream: vllm.URL, endpoint: settings.Endpoint, proxyIP: proxyIP, client: cl, proxy: px}
}

// chatOnce drives one OpenAI-shaped chat for model through the tunnel, retrying
// to absorb first-call tunnel/DNS jitter, and returns the response body.
func chatOnce(t *testing.T, ctx context.Context, env pricedEnv, model, sessionID string) string {
	t.Helper()
	var code int
	var body string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		c, b, cerr := env.client.Chat(ctx, env.endpoint, env.proxyIP, harness.WireChat, model, "Reply with exactly: pong", sessionID)
		if cerr == nil {
			code, body = c, b
			if code == 200 {
				break
			}
		}
		time.Sleep(5 * time.Second)
	}
	require.Equal(t, 200, code,
		"chat for %s must return 200; body: %s\n=== proxy logs ===\n%s", model, body, env.proxy.Logs(context.Background()))
	return body
}

// findAccessLogBySession polls the access-log page for the row carrying sessionID.
func findAccessLogBySession(t *testing.T, ctx context.Context, sessionID string) api.AgentNetworkAccessLog {
	t.Helper()
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
	}, 30*time.Second, 2*time.Second, "session id %q must be recorded in an access-log row", sessionID)
	return row
}

// assertOpenAICostAtRates asserts an access-log row's token counts and every cost
// bucket match the mock's fixed usage priced at the given operator rates. The
// openai surface has no cache-write bucket and the mock reports no cache tokens,
// so the whole cost is input + output; cache costs must be exactly zero.
func assertOpenAICostAtRates(t *testing.T, row api.AgentNetworkAccessLog, inRate, outRate float64) {
	t.Helper()
	wantInput := float64(vllmPromptTokens) / 1000 * inRate
	wantOutput := float64(vllmCompletionTokens) / 1000 * outRate
	wantTotal := wantInput + wantOutput

	model := ""
	if row.Model != nil {
		model = *row.Model
	}
	t.Logf("[cost] model=%s in=%d out=%d rates in/out=%.4f/%.4f stored input/output/total=$%.6f/$%.6f/$%.6f expected input/output/total=$%.6f/$%.6f/$%.6f",
		model, row.InputTokens, row.OutputTokens, inRate, outRate,
		row.InputCostUsd, row.OutputCostUsd, row.CostUsd, wantInput, wantOutput, wantTotal)

	assert.EqualValues(t, vllmPromptTokens, row.InputTokens, "prompt tokens from the mock usage block")
	assert.EqualValues(t, vllmCompletionTokens, row.OutputTokens, "completion tokens from the mock usage block")
	assert.InDeltaf(t, wantInput, row.InputCostUsd, 1e-6, "input_cost_usd must be prompt tokens at the operator input rate")
	assert.InDeltaf(t, wantOutput, row.OutputCostUsd, 1e-6, "output_cost_usd must be completion tokens at the operator output rate")
	assert.InDeltaf(t, wantTotal, row.CostUsd, 1e-6, "cost_usd must be the sum of the priced buckets")
	assert.Zerof(t, row.CachedInputCostUsd, "no cache-read tokens, so cached_input_cost_usd must be 0")
	assert.Zerof(t, row.CacheCreationCostUsd, "openai surface has no cache-write bucket, so cache_creation_cost_usd must be 0")
	assert.Zerof(t, row.CacheCostUsd, "no cache usage, so cache_cost_usd must be 0")
	assert.InDeltaf(t, row.InputCostUsd+row.OutputCostUsd, row.CostUsd, 1e-9, "stored buckets must sum to cost_usd")
}

// verifyUsageRowForSession re-checks the persisted usage row for a session
// directly in the management sqlite store — the same audit an operator runs on a
// production store.db — asserting its cost buckets match the operator rates.
func verifyUsageRowForSession(t *testing.T, sessionID string, inRate, outRate float64) {
	t.Helper()
	dbPath, err := srv.SnapshotStoreDB(t.TempDir())
	require.NoError(t, err, "snapshot management sqlite store")

	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	require.NoError(t, err, "open store snapshot")
	sqlDB, err := db.DB()
	require.NoError(t, err)
	defer func() { _ = sqlDB.Close() }()

	var provider, model string
	var inTok, outTok, cachedTok, cacheCreateTok int64
	var inCost, cachedInCost, cacheCreateCost, outCost float64
	row := db.Raw(`SELECT provider, model, input_tokens, output_tokens, cached_input_tokens, cache_creation_tokens,
	  input_cost_usd, cached_input_cost_usd, cache_creation_cost_usd, output_cost_usd
	  FROM agent_network_request_usage WHERE session_id = ? ORDER BY timestamp DESC LIMIT 1`, sessionID).Row()
	require.NoError(t, row.Scan(&provider, &model, &inTok, &outTok, &cachedTok, &cacheCreateTok,
		&inCost, &cachedInCost, &cacheCreateCost, &outCost),
		"a usage row must exist for session %q", sessionID)

	wantInput := float64(inTok) / 1000 * inRate
	wantOutput := float64(outTok) / 1000 * outRate
	t.Logf("[sql] session=%s %s/%s in=%d out=%d stored input/cached/create/output=$%.6f/$%.6f/$%.6f/$%.6f",
		sessionID, provider, model, inTok, outTok, inCost, cachedInCost, cacheCreateCost, outCost)
	assert.EqualValues(t, vllmPromptTokens, inTok, "usage row prompt tokens")
	assert.EqualValues(t, vllmCompletionTokens, outTok, "usage row completion tokens")
	assert.InDeltaf(t, wantInput, inCost, 1e-6, "usage input_cost_usd must be prompt tokens at the operator input rate")
	assert.InDeltaf(t, wantOutput, outCost, 1e-6, "usage output_cost_usd must be completion tokens at the operator output rate")
	assert.Zerof(t, cachedInCost, "usage cached_input_cost_usd must be 0 (no cache usage)")
	assert.Zerof(t, cacheCreateCost, "usage cache_creation_cost_usd must be 0 (no cache usage)")
}

// TestCustomModelPricing proves an operator can serve a model that is NOT in
// NetBird's compiled catalog, at prices they type themselves, and that those
// operator prices drive the recorded cost end to end — access log AND usage
// ledger. The provider enumerates one made-up model id at deliberately odd rates
// (no default entry could supply them), the client requests it, and every cost
// bucket must equal the mock's fixed token counts multiplied by those rates.
func TestCustomModelPricing(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	const (
		customModel = "e2e-custom-model" // absent from the compiled catalog
		inRate      = 0.037              // odd rates so a stray default can't match
		outRate     = 0.089
	)

	env := provisionPricedProvider(t, ctx, "custommodel", []api.AgentNetworkProviderModel{
		{Id: customModel, InputPer1k: inRate, OutputPer1k: outRate},
	})

	sessionID := "e2e-session-custommodel"
	body := chatOnce(t, ctx, env, customModel, sessionID)
	require.Contains(t, body, "chat.completion", "body should be an OpenAI-compatible completion; got: %s", body)

	row := findAccessLogBySession(t, ctx, sessionID)
	require.NotNil(t, row.Model, "access-log row must carry the requested model")
	assert.Equal(t, customModel, *row.Model, "the row must be stamped with the requested (custom) model, not the mock's response model")
	assertOpenAICostAtRates(t, row, inRate, outRate)

	// Metering: the uncapped token limit switches on usage recording, so the
	// request must surface as a consumption row with positive tokens and cost.
	require.Eventually(t, func() bool {
		rows, lerr := srv.ListConsumption(ctx)
		if lerr != nil {
			return false
		}
		for _, r := range rows {
			if r.TokensInput > 0 && r.TokensOutput > 0 && r.CostUsd > 0 {
				return true
			}
		}
		return false
	}, 60*time.Second, 3*time.Second, "custom-model usage must be metered into a consumption row with positive cost")

	// Final raw-SQL audit: bypass the API and re-verify the persisted usage row.
	verifyUsageRowForSession(t, sessionID, inRate, outRate)
}

// TestPriceChangeUpdatesRecordedCost proves that changing a provider's model
// price is reflected in the cost recorded for subsequent requests — in both the
// access log and the usage ledger — while requests already priced at the old
// rate keep their original cost. The update propagates to the connected proxy
// live (a mapping push rebuilds the cost_meter chain with the new table), so no
// reconnect or restart is needed; the test polls a fresh request until the new
// rate lands.
func TestPriceChangeUpdatesRecordedCost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	const (
		customModel = "e2e-repriced-model"
		inRateA     = 0.010
		outRateA    = 0.020
		inRateB     = 0.050 // 5x / 4x the original, so a repriced row is unmistakable
		outRateB    = 0.080
	)

	env := provisionPricedProvider(t, ctx, "reprice", []api.AgentNetworkProviderModel{
		{Id: customModel, InputPer1k: inRateA, OutputPer1k: outRateA},
	})

	// Phase 1 — request priced at the original rate A.
	sessionA := "e2e-session-reprice-a"
	chatOnce(t, ctx, env, customModel, sessionA)
	rowA := findAccessLogBySession(t, ctx, sessionA)
	assertOpenAICostAtRates(t, rowA, inRateA, outRateA)
	verifyUsageRowForSession(t, sessionA, inRateA, outRateA)

	// Change the model's price. The API key is omitted so the stored one is kept;
	// the models array is re-sent with the new rates (PUT replaces the list).
	// This reconciles synchronously and pushes a fresh cost_meter table to the
	// already-connected proxy — no reconnect.
	_, err := srv.UpdateProvider(ctx, env.provID, api.AgentNetworkProviderRequest{
		Name:        "reprice",
		ProviderId:  "openai_api",
		UpstreamUrl: env.upstream,
		Enabled:     ptr(true),
		Models: &[]api.AgentNetworkProviderModel{
			{Id: customModel, InputPer1k: inRateB, OutputPer1k: outRateB},
		},
	})
	require.NoError(t, err, "update provider price")

	// Phase 2 — the push + chain rebuild is async, so drive fresh requests (each
	// under its own session) until one is priced at the new rate B. Each iteration
	// fires one request and waits for that session's row to be ingested before
	// reading its cost, so an un-ingested row is never mistaken for "still rate A".
	// The expected new input cost is unmistakably higher than rate A, so a
	// lingering old-rate row can't satisfy the check.
	wantInputB := float64(vllmPromptTokens) / 1000 * inRateB
	var repriced api.AgentNetworkAccessLog
	var lastSession string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		lastSession = fmt.Sprintf("e2e-session-reprice-b-%d", time.Now().UnixNano())
		code, _, cerr := env.client.Chat(ctx, env.endpoint, env.proxyIP, harness.WireChat, customModel, "Reply with exactly: pong", lastSession)
		if cerr != nil || code != 200 {
			time.Sleep(5 * time.Second)
			continue
		}
		row := findAccessLogBySession(t, ctx, lastSession)
		if inDelta(row.InputCostUsd, wantInputB, 1e-6) {
			repriced = row
			break
		}
		// Still priced at the old rate — the push hasn't landed yet; retry.
		time.Sleep(5 * time.Second)
	}
	require.NotEmpty(t, repriced.Id, "a request after the price change must be priced at the new rate B; last input_cost_usd=$%.6f, wanted $%.6f\n=== proxy logs ===\n%s",
		repriced.InputCostUsd, wantInputB, env.proxy.Logs(context.Background()))

	assertOpenAICostAtRates(t, repriced, inRateB, outRateB)
	verifyUsageRowForSession(t, lastSession, inRateB, outRateB)

	// The original request keeps its original cost: repricing is not retroactive.
	rowAStill := findAccessLogBySession(t, ctx, sessionA)
	assertOpenAICostAtRates(t, rowAStill, inRateA, outRateA)
	verifyUsageRowForSession(t, sessionA, inRateA, outRateA)
}

// TestPricingDefaultsFileDrivesCost proves the operator-supplied pricing
// defaults file is what the proxy bills with. The harness configures
// server.agentNetwork.pricingDefaultsFile as a BARE FILENAME and writes that
// file into the bind-mounted datadir (see harness.PricingDefaultsFileName), so a
// pass exercises the whole chain: combined yaml → ToManagementConfig →
// pricing.LoadFile (relative path resolved against datadir) → DefaultTable →
// the synthesizer's cost_meter defaults payload → the proxy's lookup.
//
// The provider enumerates NO models, so it is a catch-all route with no
// per-provider-record pricing entry at all — the only rates that can price the
// request are the shipped defaults. The model is a real catalog model whose
// built-in rates the file replaces with deliberately odd values, so billing at
// the compiled-in rates (i.e. the file never loaded) fails the assertions.
func TestPricingDefaultsFileDrivesCost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// nil models: a gateway-style provider claiming every model. The synthesizer
	// ships no per-record entry for it, so the defaults table is its price list.
	env := provisionPricedProvider(t, ctx, "defaultsfile", nil)

	sessionID := "e2e-session-defaultsfile"
	body := chatOnce(t, ctx, env, harness.PricedDefaultModel, sessionID)
	require.Contains(t, body, "chat.completion", "body should be an OpenAI-compatible completion; got: %s", body)

	row := findAccessLogBySession(t, ctx, sessionID)
	require.NotNil(t, row.Model, "access-log row must carry the requested model")
	assert.Equal(t, harness.PricedDefaultModel, *row.Model, "the row must be stamped with the requested model")

	// The file's rates, not the compiled-in catalog rates for this model.
	assertOpenAICostAtRates(t, row, harness.PricedDefaultInputPer1k, harness.PricedDefaultOutputPer1k)
	verifyUsageRowForSession(t, sessionID, harness.PricedDefaultInputPer1k, harness.PricedDefaultOutputPer1k)
}

// TestPricingDefaultsFileLeavesOtherModelsAlone proves the defaults file merges
// per entry rather than replacing the whole table: the file names exactly one
// model, so a DIFFERENT catalog model must still bill at its compiled-in rates.
// Without this, a file that shipped as a wholesale replacement would silently
// zero-cost every model the operator didn't list, and TestPricingDefaultsFile-
// DrivesCost alone would not notice.
func TestPricingDefaultsFileLeavesOtherModelsAlone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// gpt-4o-mini is a catalog model the pricing file does NOT mention, so it must
	// keep its built-in rates. Pinned here independently of the catalog source so
	// a rate change in either place surfaces as a failure to reconcile rather
	// than passing silently.
	const (
		untouchedModel = "gpt-4o-mini"
		builtinInRate  = 0.00015
		builtinOutRate = 0.0006
	)

	env := provisionPricedProvider(t, ctx, "defaultsfileother", nil)

	sessionID := "e2e-session-defaultsfile-other"
	chatOnce(t, ctx, env, untouchedModel, sessionID)

	row := findAccessLogBySession(t, ctx, sessionID)
	assertOpenAICostAtRates(t, row, builtinInRate, builtinOutRate)
	verifyUsageRowForSession(t, sessionID, builtinInRate, builtinOutRate)
}

// inDelta reports whether a and b are within tol of each other.
func inDelta(a, b, tol float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d <= tol
}
