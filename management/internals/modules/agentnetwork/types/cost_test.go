package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// costRow builds an access-log entry carrying only a cost breakdown — the rest
// of the row is irrelevant to the summation identities under test.
func costRow(id, session string, ts time.Time, in, cachedIn, cacheCreate, out float64) *AgentNetworkAccessLog {
	return &AgentNetworkAccessLog{
		ID:                   id,
		SessionID:            session,
		Timestamp:            ts,
		InputCostUSD:         in,
		CachedInputCostUSD:   cachedIn,
		CacheCreationCostUSD: cacheCreate,
		OutputCostUSD:        out,
	}
}

// TestAPIResponse_CostComponentsSumToAggregates is the contract a client adding
// up an API response depends on: within a single rendered object, the four
// per-bucket fields sum to cost_usd, and the two cache fields sum to
// cache_cost_usd. Uses rates that are not exactly representable in binary
// floating point, so the identity is checked against real arithmetic rather
// than round numbers.
func TestAPIResponse_CostComponentsSumToAggregates(t *testing.T) {
	row := costRow("r1", "s1", time.Now(), 0.000768, 0.0002304, 0.00192, 0.003)

	api := row.ToAPIResponse()
	assert.InDelta(t, api.InputCostUsd+api.CachedInputCostUsd+api.CacheCreationCostUsd+api.OutputCostUsd,
		api.CostUsd, 1e-12, "rendered buckets must sum to the rendered cost_usd")
	assert.InDelta(t, api.CachedInputCostUsd+api.CacheCreationCostUsd, api.CacheCostUsd, 1e-12,
		"rendered cache buckets must sum to the rendered cache_cost_usd")
	assert.InDelta(t, 0.0059184, api.CostUsd, 1e-12, "total is the exact sum, not a separately rounded figure")
	assert.InDelta(t, 0.0021504, api.CacheCostUsd, 1e-12, "cache cost is the exact sum of the two cache buckets")
}

// TestSessionSummary_SumsMatchSummedEntries proves a session summary equals the
// sum of the entries it renders: a client that adds up the entries itself must
// land on the same number the summary reports, per bucket and in total.
func TestSessionSummary_SumsMatchSummedEntries(t *testing.T) {
	base := time.Date(2026, 5, 5, 10, 0, 0, 0, time.UTC)
	entries := []*AgentNetworkAccessLog{
		costRow("r1", "s1", base, 0.000768, 0.0002304, 0.00192, 0.003),
		costRow("r2", "s1", base.Add(time.Minute), 0.000625, 0.0009375, 0, 0.005),
		costRow("r3", "s1", base.Add(2*time.Minute), 0.0000016, 0, 0, 0.0000032),
	}

	sessions := FoldAccessLogSessions([]string{"s1"}, entries)
	require.Len(t, sessions, 1)
	sess := sessions[0].ToAPIResponse()

	var wantInput, wantCachedInput, wantCacheCreation, wantOutput float64
	for _, e := range entries {
		wantInput += e.InputCostUSD
		wantCachedInput += e.CachedInputCostUSD
		wantCacheCreation += e.CacheCreationCostUSD
		wantOutput += e.OutputCostUSD
	}

	assert.InDelta(t, wantInput, sess.InputCostUsd, 1e-12, "session input cost is the sum of its entries")
	assert.InDelta(t, wantCachedInput, sess.CachedInputCostUsd, 1e-12, "session cache-read cost is the sum of its entries")
	assert.InDelta(t, wantCacheCreation, sess.CacheCreationCostUsd, 1e-12, "session cache-write cost is the sum of its entries")
	assert.InDelta(t, wantOutput, sess.OutputCostUsd, 1e-12, "session output cost is the sum of its entries")
	assert.InDelta(t, wantInput+wantCachedInput+wantCacheCreation+wantOutput, sess.CostUsd, 1e-12,
		"session total equals the summed entry buckets")

	// Summing the rendered entries must give the same answer as reading the
	// summary — the property a UI relies on when it totals a table itself.
	var fromEntries float64
	for _, e := range sess.Entries {
		fromEntries += e.CostUsd
	}
	assert.InDelta(t, sess.CostUsd, fromEntries, 1e-12, "summary total must match the summed rendered entries")

	// The sub-microdollar row must still contribute; it would vanish under
	// 6-decimal quantisation.
	assert.Greater(t, sess.InputCostUsd, 0.001393, "small-cost rows must not be quantised away")
}

// TestUsageBuckets_SumsMatchSummedRows proves the same identity one level up:
// a usage bucket equals the sum of the ledger rows folded into it, and the
// buckets together equal the whole range.
func TestUsageBuckets_SumsMatchSummedRows(t *testing.T) {
	day1 := time.Date(2026, 5, 5, 9, 0, 0, 0, time.UTC)
	day2 := time.Date(2026, 5, 6, 9, 0, 0, 0, time.UTC)
	rows := []*AgentNetworkUsage{
		{ID: "u1", Timestamp: day1, InputCostUSD: 0.000768, CachedInputCostUSD: 0.0002304, CacheCreationCostUSD: 0.00192, OutputCostUSD: 0.003},
		{ID: "u2", Timestamp: day1.Add(time.Hour), InputCostUSD: 0.000625, CachedInputCostUSD: 0.0009375, OutputCostUSD: 0.005},
		{ID: "u3", Timestamp: day2, InputCostUSD: 0.0000016, OutputCostUSD: 0.0000032},
	}

	buckets := AggregateUsageByGranularity(rows, UsageGranularityDay)
	require.Len(t, buckets, 2, "two distinct days expected")

	var total, cache float64
	for _, b := range buckets {
		api := b.ToAPIResponse()
		assert.InDelta(t, api.InputCostUsd+api.CachedInputCostUsd+api.CacheCreationCostUsd+api.OutputCostUsd,
			api.CostUsd, 1e-12, "each bucket's components must sum to its cost_usd")
		total += api.CostUsd
		cache += api.CacheCostUsd
	}

	var wantTotal, wantCache float64
	for _, r := range rows {
		wantTotal += r.TotalCostUSD()
		wantCache += r.CacheCostUSD()
	}
	assert.InDelta(t, wantTotal, total, 1e-12, "buckets must sum to the total across all ledger rows")
	assert.InDelta(t, wantCache, cache, 1e-12, "buckets must sum to the cache spend across all ledger rows")

	// A month bucket over the same rows must total identically — regrouping
	// changes the partition, never the sum.
	monthly := AggregateUsageByGranularity(rows, UsageGranularityMonth)
	require.Len(t, monthly, 1)
	assert.InDelta(t, wantTotal, monthly[0].ToAPIResponse().CostUsd, 1e-12,
		"re-bucketing at a different granularity must preserve the total")
}
