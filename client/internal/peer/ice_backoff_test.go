package peer

import (
	"testing"
	"time"
)

// TestIceBackoff_AllowActivityOverride pins down the rate-limited
// "user-activity-overrides-hourly-backoff" semantic added 2026-05-05.
// Codex review caught that markSuccess() previously did NOT stamp
// lastResetAt, so this test specifically also covers the post-success
// path -- without the markSuccess fix the rate-limit window would have
// effectively never engaged after a brief successful connect cycle.
func TestIceBackoff_AllowActivityOverride(t *testing.T) {
	s := newIceBackoff(15 * time.Minute)

	// Not suspended -> no override needed
	if s.AllowActivityOverride() {
		t.Fatal("not suspended: must NOT allow override")
	}

	// Suspended via markFailure
	for i := 0; i < 3; i++ {
		s.markFailure()
	}
	if !s.IsSuspended() {
		t.Fatal("after 3 failures: must be suspended")
	}

	// Recently reset (Reset just happened in newIceBackoff bo, but
	// lastResetAt is zero — falls back to time.Since(zero) = forever
	// which IS > 5min, so override IS allowed). To make the test
	// deterministic, hard-Reset to stamp lastResetAt = now, then
	// re-fail 3x to suspend.
	s.Reset()
	for i := 0; i < 3; i++ {
		s.markFailure()
	}
	if !s.IsSuspended() {
		t.Fatal("after Reset+3 failures: must be suspended")
	}
	// Now lastResetAt is fresh (within 5min) -> override DENIED
	if s.AllowActivityOverride() {
		t.Fatal("recently reset: must NOT allow override (rate-limit)")
	}

	// Simulate >5min since last reset by stamping lastResetAt back
	s.mu.Lock()
	s.lastResetAt = time.Now().Add(-6 * time.Minute)
	s.mu.Unlock()
	if !s.AllowActivityOverride() {
		t.Fatal("suspended + last reset >5min ago: MUST allow override")
	}
}

// TestIceBackoff_OnlyMarkFailureMutates pins the invariant Codex review
// 2026-05-05 asked us to make explicit: the backoff state is mutated
// by exactly three methods (markFailure, markSuccess, Reset) and by
// nothing else. In particular, the backoff must NEVER be triggered by
// inactivity-driven ICE-detach (DetachICEForPeer / lazy-mgr's
// ICEInactiveChan) or by full-conn-close (lazy-mgr relayTimeout).
//
// Test approach: spin a backoff, exercise the read-only paths
// (Snapshot, IsSuspended, AllowActivityOverride) repeatedly, then
// assert failures stayed at 0 and suspended stayed false. This proves
// that the read methods don't have side-effects that would
// accidentally enter the backoff state.
func TestIceBackoff_OnlyMarkFailureMutates(t *testing.T) {
	s := newIceBackoff(15 * time.Minute)

	for i := 0; i < 20; i++ {
		_ = s.IsSuspended()
		_ = s.Snapshot()
		_ = s.AllowActivityOverride()
	}

	if s.IsSuspended() {
		t.Fatal("backoff must not be suspended after read-only calls")
	}
	snap := s.Snapshot()
	if snap.Failures != 0 || snap.Suspended {
		t.Fatalf("read-only calls must not mutate state, got %+v", snap)
	}
}

// TestIceBackoff_MarkSuccessStampsLastResetAt is a direct regression
// pin for the Codex-found inconsistency: markSuccess MUST update
// lastResetAt so it counts as a reset point for the
// activity-override rate limit (and the markFailure grace period).
func TestIceBackoff_MarkSuccessStampsLastResetAt(t *testing.T) {
	s := newIceBackoff(15 * time.Minute)
	// Force lastResetAt into the past
	s.mu.Lock()
	s.lastResetAt = time.Now().Add(-30 * time.Minute)
	s.mu.Unlock()

	s.markSuccess()

	s.mu.Lock()
	stamped := s.lastResetAt
	s.mu.Unlock()
	if time.Since(stamped) > time.Second {
		t.Fatalf("markSuccess must stamp lastResetAt to ~now, got %v ago", time.Since(stamped))
	}
}


func TestIceBackoff_InitialState(t *testing.T) {
	s := newIceBackoff(15 * time.Minute)
	if s.IsSuspended() {
		t.Fatal("fresh state must not be suspended")
	}
	snap := s.Snapshot()
	if snap.Failures != 0 || snap.Suspended {
		t.Fatalf("fresh state snapshot wrong: %+v", snap)
	}
}

func TestIceBackoff_SetMaxBackoff_Live(t *testing.T) {
	s := newIceBackoff(1 * time.Minute) // tight cap
	s.markFailure()                     // expect ~1m
	s.markFailure()                     // expect ~1m (capped)
	d2 := s.markFailure()               // still ~1m
	if d2 > 90*time.Second {
		t.Errorf("with 1m cap, third failure should be ~1m, got %v", d2)
	}
	// Live update to 1h cap
	s.SetMaxBackoff(60 * time.Minute)
	// Subsequent failure produces a non-zero delay (jitter-dependent
	// but should be > 0 since backoff was rebuilt).
	d3 := s.markFailure()
	if d3 <= 0 {
		t.Errorf("after SetMaxBackoff: must produce non-zero delay, got %v", d3)
	}
}

func TestIceBackoff_SuccessReset(t *testing.T) {
	s := newIceBackoff(15 * time.Minute)
	for i := 0; i < 5; i++ {
		s.markFailure()
	}
	s.markSuccess()
	snap := s.Snapshot()
	if snap.Failures != 0 || snap.Suspended {
		t.Fatalf("after markSuccess: %+v", snap)
	}
	// Next failure must be back to step-1 magnitude (~1m)
	delay := s.markFailure()
	if delay > 70*time.Second {
		t.Errorf("after success-reset, first failure must restart at ~1m, got %v", delay)
	}
}

func TestIceBackoff_HardReset(t *testing.T) {
	s := newIceBackoff(15 * time.Minute)
	s.markFailure()
	s.markFailure()
	s.Reset()
	snap := s.Snapshot()
	if snap.Failures != 0 || snap.Suspended {
		t.Fatalf("after Reset: %+v", snap)
	}
}

func TestIceBackoff_SuspendedExpires(t *testing.T) {
	s := newIceBackoff(15 * time.Minute)
	s.markFailure()
	// Force nextRetry to past
	s.mu.Lock()
	s.nextRetry = time.Now().Add(-1 * time.Second)
	s.mu.Unlock()
	if s.IsSuspended() {
		t.Fatal("expired suspend must report not suspended")
	}
}

func TestIceBackoff_ExponentialDoubling(t *testing.T) {
	s := newIceBackoff(15 * time.Minute)
	expectedRanges := []struct {
		min, max time.Duration
	}{
		{50 * time.Second, 70 * time.Second},   // ~1m
		{100 * time.Second, 140 * time.Second}, // ~2m
		{210 * time.Second, 270 * time.Second}, // ~4m
		{420 * time.Second, 540 * time.Second}, // ~8m
		{810 * time.Second, 990 * time.Second}, // ~15m capped
		{810 * time.Second, 990 * time.Second}, // ~15m capped
		{810 * time.Second, 990 * time.Second}, // ~15m capped
	}
	for i, exp := range expectedRanges {
		delay := s.markFailure()
		if delay < exp.min || delay > exp.max {
			t.Errorf("failure #%d: delay %v outside expected range [%v, %v]",
				i+1, delay, exp.min, exp.max)
		}
	}
}

func TestIceBackoff_MaxBackoffOverride(t *testing.T) {
	s := newIceBackoff(5 * time.Minute) // 300s cap
	delays := []time.Duration{}
	for i := 0; i < 5; i++ {
		delays = append(delays, s.markFailure())
	}
	// Last few should be capped at ~5m (300s) regardless of multiplier
	for i := 2; i < 5; i++ {
		if delays[i] > 6*time.Minute {
			t.Errorf("failure #%d: delay %v exceeds 5m cap", i+1, delays[i])
		}
	}
}

func TestIceBackoff_MaxBackoffZero_Disabled(t *testing.T) {
	s := newIceBackoff(0)
	delay := s.markFailure()
	if delay != 0 {
		t.Errorf("disabled backoff must return 0 delay, got %v", delay)
	}
	if s.IsSuspended() {
		t.Fatal("disabled backoff must not suspend")
	}
}

func TestIceBackoff_GracePeriodAfterReset_ShortDelay(t *testing.T) {
	s := newIceBackoff(15 * time.Minute)
	s.Reset() // simulate srReconnect / network-change

	delay := s.markFailure()
	if delay != networkChangeRetryDelay {
		t.Fatalf("within grace window: expected %v, got %v", networkChangeRetryDelay, delay)
	}

	// A second failure inside the grace window also uses the short delay
	// (long-term exponential schedule is NOT advanced).
	delay2 := s.markFailure()
	if delay2 != networkChangeRetryDelay {
		t.Fatalf("second failure inside grace: expected %v, got %v", networkChangeRetryDelay, delay2)
	}
}

func TestIceBackoff_GraceExpired_NormalExponential(t *testing.T) {
	s := newIceBackoff(15 * time.Minute)
	s.Reset()

	// Force lastResetAt into the past so the grace window has expired.
	s.mu.Lock()
	s.lastResetAt = time.Now().Add(-2 * networkChangeGracePeriod)
	s.mu.Unlock()

	delay := s.markFailure()
	if delay < 50*time.Second || delay > 70*time.Second {
		t.Fatalf("outside grace: expected ~1m exponential delay, got %v", delay)
	}
}

func TestIceBackoff_NoGraceWithoutReset(t *testing.T) {
	// Fresh state without an explicit Reset must use the normal exponential
	// schedule (lastResetAt is zero so the grace path does not apply).
	s := newIceBackoff(15 * time.Minute)
	delay := s.markFailure()
	if delay < 50*time.Second {
		t.Fatalf("fresh state without Reset: expected ~1m delay, got %v", delay)
	}
}

func TestIceBackoff_FirstFailure(t *testing.T) {
	s := newIceBackoff(15 * time.Minute)
	delay := s.markFailure()
	if delay <= 0 {
		t.Fatalf("first failure must produce a positive delay, got %v", delay)
	}
	if delay < 50*time.Second || delay > 70*time.Second {
		t.Fatalf("first failure delay should be ~1m (with 10%% jitter), got %v", delay)
	}
	if !s.IsSuspended() {
		t.Fatal("after first failure must be suspended")
	}
	snap := s.Snapshot()
	if snap.Failures != 1 || !snap.Suspended {
		t.Fatalf("snapshot wrong: %+v", snap)
	}
}
