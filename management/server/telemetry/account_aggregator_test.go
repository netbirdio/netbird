package telemetry

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeltaTemporality_P95ReflectsCurrentWindow(t *testing.T) {
	// Verify that with delta temporality, each flush window only reflects
	// recordings since the last flush — not all-time data.
	ctx := context.Background()
	agg := NewAccountDurationAggregator(ctx, time.Minute, 5*time.Minute)
	defer func(agg *AccountDurationAggregator) {
		err := agg.Shutdown()
		if err != nil {
			t.Errorf("failed to shutdown aggregator: %v", err)
		}
	}(agg)

	// Window 1: Record 100 slow requests (500ms each)
	for range 100 {
		agg.Record("account-A", 500*time.Millisecond)
	}

	p95sWindow1 := agg.FlushAndGetP95s()
	require.Len(t, p95sWindow1, 1, "should have P95 for one account")
	firstP95 := p95sWindow1[0]
	assert.GreaterOrEqual(t, firstP95, int64(200),
		"first window P95 should reflect the 500ms recordings")

	// Window 2: Record 100 FAST requests (10ms each)
	for range 100 {
		agg.Record("account-A", 10*time.Millisecond)
	}

	p95sWindow2 := agg.FlushAndGetP95s()
	require.Len(t, p95sWindow2, 1, "should have P95 for one account")
	secondP95 := p95sWindow2[0]

	// With delta temporality the P95 should drop significantly because
	// the first window's slow recordings are no longer included.
	assert.Less(t, secondP95, firstP95,
		"second window P95 should be lower than first — delta temporality "+
			"ensures each window only reflects recent recordings")
}

func TestEqualWeightPerAccount(t *testing.T) {
	// Verify that each account contributes exactly one P95 value,
	// regardless of how many requests it made.
	ctx := context.Background()
	agg := NewAccountDurationAggregator(ctx, time.Minute, 5*time.Minute)
	defer func(agg *AccountDurationAggregator) {
		err := agg.Shutdown()
		if err != nil {
			t.Errorf("failed to shutdown aggregator: %v", err)
		}
	}(agg)

	// Account A: 10,000 requests at 500ms (noisy customer)
	for range 10000 {
		agg.Record("account-A", 500*time.Millisecond)
	}

	// Accounts B, C, D: 10 requests each at 50ms (normal customers)
	for _, id := range []string{"account-B", "account-C", "account-D"} {
		for range 10 {
			agg.Record(id, 50*time.Millisecond)
		}
	}

	p95s := agg.FlushAndGetP95s()

	// Should get exactly 4 P95 values — one per account
	assert.Len(t, p95s, 4, "each account should contribute exactly one P95")
}

func TestStaleAccountEviction(t *testing.T) {
	ctx := context.Background()
	// Use a very short MaxAge so we can test staleness
	agg := NewAccountDurationAggregator(ctx, time.Minute, 50*time.Millisecond)
	defer func(agg *AccountDurationAggregator) {
		err := agg.Shutdown()
		if err != nil {
			t.Errorf("failed to shutdown aggregator: %v", err)
		}
	}(agg)

	agg.Record("account-A", 100*time.Millisecond)
	agg.Record("account-B", 200*time.Millisecond)

	// Both accounts should appear
	p95s := agg.FlushAndGetP95s()
	assert.Len(t, p95s, 2, "both accounts should have P95 values")

	// Wait for account-A to become stale, then only update account-B
	time.Sleep(60 * time.Millisecond)
	agg.Record("account-B", 200*time.Millisecond)

	p95s = agg.FlushAndGetP95s()
	assert.Len(t, p95s, 1, "both accounts should have P95 values")

	// account-A should have been evicted from the accounts map
	agg.mu.RLock()
	_, accountAExists := agg.accounts["account-A"]
	_, accountBExists := agg.accounts["account-B"]
	agg.mu.RUnlock()

	assert.False(t, accountAExists, "stale account-A should be evicted from map")
	assert.True(t, accountBExists, "active account-B should remain in map")
}

func TestStaleAccountEviction_DoesNotReappear(t *testing.T) {
	// Verify that with delta temporality, an evicted stale account does not
	// reappear in subsequent flushes.
	ctx := context.Background()
	agg := NewAccountDurationAggregator(ctx, time.Minute, 50*time.Millisecond)
	defer func(agg *AccountDurationAggregator) {
		err := agg.Shutdown()
		if err != nil {
			t.Errorf("failed to shutdown aggregator: %v", err)
		}
	}(agg)

	agg.Record("account-stale", 100*time.Millisecond)

	// Wait for it to become stale
	time.Sleep(60 * time.Millisecond)

	// First flush: should detect staleness and evict
	_ = agg.FlushAndGetP95s()

	agg.mu.RLock()
	_, exists := agg.accounts["account-stale"]
	agg.mu.RUnlock()
	assert.False(t, exists, "account should be evicted after first flush")

	// Second flush: with delta temporality, the stale account should NOT reappear
	p95sSecond := agg.FlushAndGetP95s()
	assert.Empty(t, p95sSecond,
		"evicted account should not reappear in subsequent flushes with delta temporality")
}

func TestP95Calculation_SingleSample(t *testing.T) {
	ctx := context.Background()
	agg := NewAccountDurationAggregator(ctx, time.Minute, 5*time.Minute)
	defer func(agg *AccountDurationAggregator) {
		err := agg.Shutdown()
		if err != nil {
			t.Errorf("failed to shutdown aggregator: %v", err)
		}
	}(agg)

	agg.Record("account-A", 150*time.Millisecond)

	p95s := agg.FlushAndGetP95s()
	require.Len(t, p95s, 1)
	// With a single sample, P95 should be the bucket bound containing 150ms
	assert.Greater(t, p95s[0], int64(0), "P95 of a single sample should be positive")
}

func TestP95Calculation_AllSameValue(t *testing.T) {
	ctx := context.Background()
	agg := NewAccountDurationAggregator(ctx, time.Minute, 5*time.Minute)
	defer func(agg *AccountDurationAggregator) {
		err := agg.Shutdown()
		if err != nil {
			t.Errorf("failed to shutdown aggregator: %v", err)
		}
	}(agg)

	// All samples are 100ms — P95 should be the bucket bound containing 100ms
	for range 100 {
		agg.Record("account-A", 100*time.Millisecond)
	}

	p95s := agg.FlushAndGetP95s()
	require.Len(t, p95s, 1)
	assert.Greater(t, p95s[0], int64(0))
}

func TestMultipleAccounts_IndependentP95s(t *testing.T) {
	ctx := context.Background()
	agg := NewAccountDurationAggregator(ctx, time.Minute, 5*time.Minute)
	defer func(agg *AccountDurationAggregator) {
		err := agg.Shutdown()
		if err != nil {
			t.Errorf("failed to shutdown aggregator: %v", err)
		}
	}(agg)

	// Account A: all fast (10ms)
	for range 100 {
		agg.Record("account-fast", 10*time.Millisecond)
	}

	// Account B: all slow (5000ms)
	for range 100 {
		agg.Record("account-slow", 5000*time.Millisecond)
	}

	p95s := agg.FlushAndGetP95s()
	require.Len(t, p95s, 2, "should have two P95 values")

	// Find min and max — they should differ significantly
	minP95 := p95s[0]
	maxP95 := p95s[1]
	if minP95 > maxP95 {
		minP95, maxP95 = maxP95, minP95
	}

	assert.Less(t, minP95, int64(1000),
		"fast account P95 should be well under 1000ms")
	assert.Greater(t, maxP95, int64(1000),
		"slow account P95 should be well over 1000ms")
}
