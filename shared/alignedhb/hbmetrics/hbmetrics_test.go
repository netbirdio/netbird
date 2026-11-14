package hbmetrics

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/alignedhb/hbmetrics/hbmetricstest"
)

func TestMetricsCount(t *testing.T) {
	meter, reader := hbmetricstest.NewMeter()
	m, err := New(meter, "relay_")
	require.NoError(t, err)

	ctx := context.Background()
	m.HeartbeatSent(ctx)
	m.HeartbeatSent(ctx)
	m.CorrectionApplied(ctx)
	m.CorrectionIgnored(ctx, IgnoreRateLimit)
	m.CorrectionIgnored(ctx, IgnoreAtWindowEdge)
	m.CorrectionIgnored(ctx, IgnoreAtWindowEdge)
	m.ClampHit(ctx)
	m.BadSignature(ctx)

	assert.Equal(t, map[string]int64{
		"relay_aligned_heartbeat_sent_total":                               2,
		"relay_aligned_heartbeat_corrections_applied_total":                1,
		"relay_aligned_heartbeat_corrections_ignored_total/rate_limit":     1,
		"relay_aligned_heartbeat_corrections_ignored_total/at_window_edge": 2,
		"relay_aligned_heartbeat_clamp_hits_total":                         1,
		"relay_aligned_heartbeat_bad_signatures_total":                     1,
	}, hbmetricstest.Counts(t, reader), "counters by name and reason")
}

func TestNilMetricsCountNothing(t *testing.T) {
	var m *Metrics
	ctx := context.Background()
	assert.NotPanics(t, func() {
		m.HeartbeatSent(ctx)
		m.CorrectionApplied(ctx)
		m.CorrectionIgnored(ctx, IgnoreStock)
		m.ClampHit(ctx)
		m.BadSignature(ctx)
	}, "nil metrics are a no-op")
}

func TestClampStreakWarnsOnce(t *testing.T) {
	var c ClampStreak
	for i := 1; i < ClampWarnAfter; i++ {
		assert.False(t, c.Hit("signal", "peer"), "hit %d below the limit", i)
	}
	assert.True(t, c.Hit("signal", "peer"), "warns at the limit")
	assert.False(t, c.Hit("signal", "peer"), "warns once")

	c.Reset()
	for i := 1; i <= ClampWarnAfter; i++ {
		assert.False(t, c.Hit("signal", "peer"), "new streak, hit %d", i)
	}
}

func TestClampStreakResetBeforeLimit(t *testing.T) {
	var c ClampStreak
	for i := 1; i < ClampWarnAfter; i++ {
		assert.False(t, c.Hit("signal", "peer"), "hit %d below the limit", i)
	}
	c.Reset()
	for i := 1; i < ClampWarnAfter; i++ {
		assert.False(t, c.Hit("signal", "peer"), "new streak, hit %d", i)
	}
	assert.True(t, c.Hit("signal", "peer"), "warns at the limit of the new streak")
}
