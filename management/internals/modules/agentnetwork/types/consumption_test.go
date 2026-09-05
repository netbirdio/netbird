package types

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestWindowStart_AlignedToUnixEpoch is the multi-node-convergence
// guarantee: any two proxies computing WindowStart(now, s) for the
// same s must land on the same boundary. The implementation aligns
// to the unix epoch (UTC) rather than local time, calendar weeks, or
// process start time — none of which are shared across nodes.
//
// Table covers the load-bearing window lengths (5m, 1h, 24h, 30d)
// plus a few odd values that still need to align cleanly.
func TestWindowStart_AlignedToUnixEpoch(t *testing.T) {
	cases := []struct {
		name          string
		instant       time.Time
		windowSeconds int64
		want          time.Time
	}{
		{
			name:          "5m window — drops seconds inside the bucket",
			instant:       time.Date(2026, 5, 6, 13, 47, 23, 0, time.UTC),
			windowSeconds: 300,
			want:          time.Date(2026, 5, 6, 13, 45, 0, 0, time.UTC),
		},
		{
			name:          "1h window — drops minutes / seconds, keeps the hour",
			instant:       time.Date(2026, 5, 6, 13, 47, 23, 0, time.UTC),
			windowSeconds: 3600,
			want:          time.Date(2026, 5, 6, 13, 0, 0, 0, time.UTC),
		},
		{
			name:          "24h window aligns to UTC midnight",
			instant:       time.Date(2026, 5, 6, 13, 47, 23, 0, time.UTC),
			windowSeconds: 86_400,
			want:          time.Date(2026, 5, 6, 0, 0, 0, 0, time.UTC),
		},
		{
			name:          "30d (2_592_000s) window aligns to the 30d epoch grid, not month boundaries",
			instant:       time.Date(2026, 5, 6, 0, 0, 0, 0, time.UTC),
			windowSeconds: 2_592_000,
			// 2026-05-06 UTC = 1778025600s; 1778025600 / 2592000 = 685
			// 685 * 2592000 = 1775520000s = 2026-04-07 00:00:00 UTC
			want: time.Date(2026, 4, 7, 0, 0, 0, 0, time.UTC),
		},
		{
			name:          "non-UTC input still anchors on UTC epoch boundaries",
			instant:       time.Date(2026, 5, 6, 13, 47, 23, 0, time.FixedZone("CEST", 2*3600)),
			windowSeconds: 86_400,
			// 2026-05-06 13:47:23 CEST = 11:47:23 UTC → bucket 2026-05-06 00:00:00 UTC
			want: time.Date(2026, 5, 6, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := WindowStart(tc.instant, tc.windowSeconds)
			assert.True(t, got.Equal(tc.want),
				"WindowStart(%v, %ds) = %v, want %v", tc.instant, tc.windowSeconds, got, tc.want)
		})
	}
}

// TestWindowStart_WithinWindowConverges proves the determinism
// contract: any two timestamps inside the same window land on the
// exact same boundary. Two proxy nodes serving requests 7s apart
// must agree on which counter row to upsert.
func TestWindowStart_WithinWindowConverges(t *testing.T) {
	t1 := time.Date(2026, 5, 6, 14, 0, 0, 0, time.UTC)
	t2 := t1.Add(7 * time.Second)
	t3 := t1.Add(59*time.Minute + 59*time.Second)

	a := WindowStart(t1, 3600)
	b := WindowStart(t2, 3600)
	c := WindowStart(t3, 3600)

	assert.True(t, a.Equal(b), "two timestamps 7s apart in the same 1h window must align to the same boundary")
	assert.True(t, a.Equal(c), "the very last second of a 1h window still lands on the SAME bucket as the first second")
}

// TestWindowStart_AcrossWindowsDiverges is the symmetric guarantee:
// two timestamps separated by a window's worth of time MUST land on
// different boundaries. Without this, a 24h window's "rollover"
// would never reset the counter.
func TestWindowStart_AcrossWindowsDiverges(t *testing.T) {
	t1 := time.Date(2026, 5, 6, 23, 59, 59, 0, time.UTC)
	t2 := t1.Add(2 * time.Second) // 2026-05-07 00:00:01

	a := WindowStart(t1, 86_400)
	b := WindowStart(t2, 86_400)
	assert.False(t, a.Equal(b),
		"timestamps straddling a 24h-window boundary must land on different buckets — otherwise daily caps never reset")
}

// TestWindowStart_DifferentWindowsHaveDifferentBuckets locks the
// design fork "two policies with different window_seconds on the same
// group produce independent counters". A 24h boundary at noon is NOT
// the same as the 30d boundary that contains it.
func TestWindowStart_DifferentWindowsHaveDifferentBuckets(t *testing.T) {
	now := time.Date(2026, 5, 6, 12, 0, 0, 0, time.UTC)
	short := WindowStart(now, 86_400)
	long := WindowStart(now, 2_592_000)
	assert.False(t, short.Equal(long),
		"the 24h bucket and 30d bucket containing the same instant must differ — independent counters require independent keys")
}

// TestWindowStart_SubMinuteAndMinuteAlignment locks sub-hour windows.
// A 5-minute window must align to multiples of 300s from the unix
// epoch — minute marks 0/5/10/.../55 within an hour, deterministic
// across nodes regardless of clock drift.
func TestWindowStart_SubMinuteAndMinuteAlignment(t *testing.T) {
	t1 := time.Date(2026, 5, 6, 14, 12, 30, 0, time.UTC)
	t2 := time.Date(2026, 5, 6, 14, 14, 59, 0, time.UTC)
	t3 := time.Date(2026, 5, 6, 14, 15, 0, 0, time.UTC)

	a := WindowStart(t1, 300)
	b := WindowStart(t2, 300)
	c := WindowStart(t3, 300)

	assert.True(t, a.Equal(b),
		"14:12:30 and 14:14:59 fall in the same 5m bucket starting at 14:10:00")
	assert.True(t, a.Equal(time.Date(2026, 5, 6, 14, 10, 0, 0, time.UTC)),
		"5m bucket containing 14:12 starts at 14:10 — aligned to multiples of 300s from unix epoch")
	assert.False(t, a.Equal(c),
		"14:15:00 is the start of the next 5m bucket — must not fold into the previous one")
}

// TestWindowStart_ZeroWindowReturnsInputUTC covers the defensive
// path: caller hands a zero / negative window (shouldn't happen, but
// might mid-refactor). The function returns the input as UTC rather
// than dividing by zero.
func TestWindowStart_ZeroWindowReturnsInputUTC(t *testing.T) {
	now := time.Date(2026, 5, 6, 12, 30, 45, 0, time.FixedZone("CEST", 2*3600))
	got := WindowStart(now, 0)
	assert.True(t, got.Equal(now.UTC()), "zero window must not panic — return input as UTC")
}
