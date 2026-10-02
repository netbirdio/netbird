package sessionwatch

import (
	"errors"
	"sync"
	"testing"
	"time"

	cProto "github.com/netbirdio/netbird/client/proto"
)

// fakeRecorder satisfies StatusRecorder and records every call so tests
// can observe what the watcher emits. SetSessionExpiresAt and PublishEvent
// land in the same ordered events slice (with the Kind distinguishing
// them) so tests that care about ordering still work. lastDeadline holds
// the most recent value passed to SetSessionExpiresAt so tests can assert
// the recorder ended up cleared/set as expected.
type fakeRecorder struct {
	mu           sync.Mutex
	events       []event
	lastDeadline time.Time
}

type eventKind int

const (
	stateChange eventKind = iota
	publish
)

type event struct {
	kind eventKind
	// Set only for publish events.
	severity cProto.SystemEvent_Severity
	category cProto.SystemEvent_Category
	message  string
	meta     map[string]string
}

// SetSessionExpiresAt mirrors peer.Status: a same-value write is a no-op,
// a real change records the new value and fans out a state-change (the
// production recorder calls notifyStateChange internally). The baseline
// is the zero time, so an initial clear before any deadline is set emits
// nothing — matching the real recorder.
func (r *fakeRecorder) SetSessionExpiresAt(deadline time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lastDeadline.Equal(deadline) {
		return
	}
	r.lastDeadline = deadline
	r.events = append(r.events, event{kind: stateChange})
}

func (r *fakeRecorder) deadline() time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastDeadline
}

func (r *fakeRecorder) PublishEvent(
	severity cProto.SystemEvent_Severity,
	category cProto.SystemEvent_Category,
	message string,
	_ string,
	metadata map[string]string,
) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event{
		kind:     publish,
		severity: severity,
		category: category,
		message:  message,
		meta:     metadata,
	})
}

func (r *fakeRecorder) snapshot() []event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]event, len(r.events))
	copy(out, r.events)
	return out
}

func (e event) isFinalWarning() bool {
	return e.kind == publish && e.meta[MetaSessionFinal] == "true"
}

func (e event) isWarning() bool {
	return e.kind == publish && e.meta[MetaSessionWarning] == "true" && e.meta[MetaSessionFinal] != "true"
}

func countWhere(events []event, pred func(event) bool) int {
	n := 0
	for _, e := range events {
		if pred(e) {
			n++
		}
	}
	return n
}

func waitForEvents(t *testing.T, r *fakeRecorder, want int) []event {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := r.snapshot(); len(got) >= want {
			return got
		}
		time.Sleep(5 * time.Millisecond)
	}
	got := r.snapshot()
	t.Fatalf("timed out waiting for %d events, got %d: %+v", want, len(got), got)
	return nil
}

// newWatcher builds a watcher with the final timer disabled (finalLead=0),
// matching the lead-only behaviour the pre-final-warning tests assume.
func newWatcher(lead time.Duration, r *fakeRecorder) *Watcher {
	return NewWithLeads(lead, 0, r)
}

func TestUpdateZeroBeforeAnythingIsNoop(t *testing.T) {
	r := &fakeRecorder{}
	w := newWatcher(50*time.Millisecond, r)
	defer w.Close()

	_ = w.Update(time.Time{})

	if got := r.snapshot(); len(got) != 0 {
		t.Fatalf("expected no events on initial zero, got %+v", got)
	}
}

func TestUpdateNonZeroFiresStateChange(t *testing.T) {
	r := &fakeRecorder{}
	w := newWatcher(50*time.Millisecond, r)
	defer w.Close()

	d := time.Now().Add(time.Hour)
	_ = w.Update(d)

	events := waitForEvents(t, r, 1)
	if events[0].kind != stateChange {
		t.Fatalf("expected stateChange, got %+v", events[0])
	}
	if !w.Deadline().Equal(d) {
		t.Fatalf("deadline mismatch: %v vs %v", w.Deadline(), d)
	}
}

func TestSameDeadlineIsNoop(t *testing.T) {
	r := &fakeRecorder{}
	w := newWatcher(50*time.Millisecond, r)
	defer w.Close()

	d := time.Now().Add(time.Hour)
	_ = w.Update(d)
	_ = w.Update(d)
	_ = w.Update(d)

	events := waitForEvents(t, r, 1)
	if len(events) != 1 {
		t.Fatalf("expected exactly 1 event for repeated same deadline, got %d: %+v", len(events), events)
	}
}

func TestWarningFiresOnceWithinLeadWindow(t *testing.T) {
	r := &fakeRecorder{}
	lead := 50 * time.Millisecond
	w := newWatcher(lead, r)
	defer w.Close()

	// Deadline 80ms out — warning should fire after ~30ms.
	d := time.Now().Add(80 * time.Millisecond)
	_ = w.Update(d)

	events := waitForEvents(t, r, 2)
	if events[0].kind != stateChange {
		t.Fatalf("event[0] should be stateChange, got %+v", events[0])
	}
	if !events[1].isWarning() {
		t.Fatalf("event[1] should be a warning publish, got %+v", events[1])
	}
}

func TestWarningFiresImmediatelyWhenAlreadyInsideWindow(t *testing.T) {
	r := &fakeRecorder{}
	w := newWatcher(time.Hour, r) // lead > delta => fire immediately
	defer w.Close()

	d := time.Now().Add(10 * time.Millisecond)
	_ = w.Update(d)

	events := waitForEvents(t, r, 2)
	if !events[1].isWarning() {
		t.Fatalf("expected immediate warning publish, got %+v", events[1])
	}
}

func TestNewDeadlineCancelsPriorTimer(t *testing.T) {
	r := &fakeRecorder{}
	lead := 50 * time.Millisecond
	w := newWatcher(lead, r)
	defer w.Close()

	first := time.Now().Add(80 * time.Millisecond) // would fire warning ~30ms in
	_ = w.Update(first)

	// Replace with a far-future deadline before the warning fires.
	time.Sleep(5 * time.Millisecond)
	second := time.Now().Add(time.Hour)
	_ = w.Update(second)

	// Wait past when first's warning would have fired.
	time.Sleep(80 * time.Millisecond)

	if n := countWhere(r.snapshot(), event.isWarning); n != 0 {
		t.Fatalf("warning fired for cancelled deadline: %+v", r.snapshot())
	}
}

func TestRefreshAfterFireArmsNewWarning(t *testing.T) {
	r := &fakeRecorder{}
	lead := 150 * time.Millisecond
	w := newWatcher(lead, r)
	defer w.Close()

	// Warning fires ~20ms in; the deadline itself stays 150ms away so the
	// replacement below lands well before it.
	first := time.Now().Add(170 * time.Millisecond)
	_ = w.Update(first)

	// Wait for stateChange + warning of the first cycle.
	waitForEvents(t, r, 2)

	// Simulate a successful extend: brand new deadline.
	second := time.Now().Add(60 * time.Millisecond)
	_ = w.Update(second)

	// 4 events total: stateChange, warning (first), stateChange, warning (second).
	events := waitForEvents(t, r, 4)
	if events[2].kind != stateChange {
		t.Fatalf("event[2] should be stateChange for the new deadline, got %+v", events[2])
	}
	if !events[3].isWarning() {
		t.Fatalf("event[3] should be a warning publish for the new deadline, got %+v", events[3])
	}
}

func TestUpdateZeroAfterNonZeroClearsState(t *testing.T) {
	r := &fakeRecorder{}
	w := newWatcher(time.Hour, r)
	defer w.Close()

	d := time.Now().Add(2 * time.Hour)
	_ = w.Update(d)
	waitForEvents(t, r, 1)

	_ = w.Update(time.Time{})

	events := waitForEvents(t, r, 2)
	if events[1].kind != stateChange {
		t.Fatalf("expected stateChange on clear, got %+v", events[1])
	}
	if !w.Deadline().IsZero() {
		t.Fatalf("Deadline should be zero after clear")
	}
}

func TestUpdateRejectsBeforeEpoch(t *testing.T) {
	r := &fakeRecorder{}
	w := newWatcher(50*time.Millisecond, r)
	defer w.Close()

	good := time.Now().Add(time.Hour)
	if err := w.Update(good); err != nil {
		t.Fatalf("seed Update: %v", err)
	}

	err := w.Update(time.Unix(-100, 0))
	if !errors.Is(err, ErrDeadlineBeforeEpoch) {
		t.Fatalf("want ErrDeadlineBeforeEpoch, got %v", err)
	}
	if !w.Deadline().IsZero() {
		t.Fatalf("rejected pre-epoch update must clear deadline; got %v", w.Deadline())
	}
}

func TestUpdateRejectsTooFarFuture(t *testing.T) {
	r := &fakeRecorder{}
	w := newWatcher(50*time.Millisecond, r)
	defer w.Close()

	good := time.Now().Add(time.Hour)
	if err := w.Update(good); err != nil {
		t.Fatalf("seed Update: %v", err)
	}

	err := w.Update(time.Now().Add(50 * 365 * 24 * time.Hour))
	if !errors.Is(err, ErrDeadlineTooFarFuture) {
		t.Fatalf("want ErrDeadlineTooFarFuture, got %v", err)
	}
	if !w.Deadline().IsZero() {
		t.Fatalf("rejected far-future update must clear deadline; got %v", w.Deadline())
	}
}

func TestUpdateRecentPastRecordedAsExpired(t *testing.T) {
	r := &fakeRecorder{}
	w := newWatcher(50*time.Millisecond, r)
	defer w.Close()

	d := time.Now().Add(-1 * time.Hour)
	if err := w.Update(d); err != nil {
		t.Fatalf("recent-past Update should succeed, got %v", err)
	}
	if !w.Deadline().Equal(d) {
		t.Fatalf("expected deadline to be recorded, got %v want %v", w.Deadline(), d)
	}
	if got := r.deadline(); !got.Equal(d) {
		t.Fatalf("recorder deadline = %v, want %v", got, d)
	}

	time.Sleep(80 * time.Millisecond)
	if n := countWhere(r.snapshot(), func(e event) bool { return e.kind == publish }); n != 0 {
		t.Fatalf("no warning events may fire for an already-past deadline, got %+v", r.snapshot())
	}
}

func TestUpdateAncientPastRejected(t *testing.T) {
	r := &fakeRecorder{}
	w := newWatcher(50*time.Millisecond, r)
	defer w.Close()

	good := time.Now().Add(time.Hour)
	if err := w.Update(good); err != nil {
		t.Fatalf("seed Update: %v", err)
	}
	// Drain the stateChange from the seed.
	waitForEvents(t, r, 1)

	err := w.Update(time.Now().Add(-31 * 24 * time.Hour))
	if !errors.Is(err, ErrDeadlineInPast) {
		t.Fatalf("want ErrDeadlineInPast, got %v", err)
	}
	if !w.Deadline().IsZero() {
		t.Fatalf("rejected ancient-past update must clear the deadline, got %v", w.Deadline())
	}
	events := waitForEvents(t, r, 2)
	if events[1].kind != stateChange {
		t.Fatalf("expected stateChange on clear, got %+v", events[1])
	}
}

func TestCloseSilencesUpdates(t *testing.T) {
	r := &fakeRecorder{}
	w := newWatcher(50*time.Millisecond, r)
	w.Close()

	if err := w.Update(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Update after Close: want nil, got %v", err)
	}
	if got := r.snapshot(); len(got) != 0 {
		t.Fatalf("expected no events after Close, got %+v", got)
	}
}

// TestCloseKeepsRecorderDeadline pins the reconnect-flap fix: the watcher
// closes on every engine restart (network change, sleep/wake) while the
// SSO deadline stays valid across those, so Close must leave the
// server-scoped recorder's value in place. The client run loop clears the
// recorder when it exits for real.
func TestCloseKeepsRecorderDeadline(t *testing.T) {
	r := &fakeRecorder{}
	w := newWatcher(time.Hour, r)

	d := time.Now().Add(2 * time.Hour)
	if err := w.Update(d); err != nil {
		t.Fatalf("seed Update: %v", err)
	}
	if got := r.deadline(); !got.Equal(d) {
		t.Fatalf("recorder deadline after Update = %v, want %v", got, d)
	}

	w.Close()

	if got := r.deadline(); !got.Equal(d) {
		t.Fatalf("recorder deadline after Close = %v, want %v", got, d)
	}
}

// TestCloseWithoutDeadlineLeavesRecorderUntouched guards the symmetric
// case: closing a watcher that never held a deadline must not emit a
// redundant clear (the recorder may legitimately hold a value written by
// some other path; the watcher only owns what it set).
func TestCloseWithoutDeadlineLeavesRecorderUntouched(t *testing.T) {
	r := &fakeRecorder{}
	w := newWatcher(time.Hour, r)

	w.Close()

	if got := r.snapshot(); len(got) != 0 {
		t.Fatalf("expected no events from Close on an empty watcher, got %+v", got)
	}
}

func TestFinalWarningFiresAfterRegularWarning(t *testing.T) {
	r := &fakeRecorder{}
	// Warning fires at deadline-80ms, final at deadline-30ms.
	w := NewWithLeads(80*time.Millisecond, 30*time.Millisecond, r)
	defer w.Close()

	d := time.Now().Add(100 * time.Millisecond)
	_ = w.Update(d)

	// Expect stateChange + warning + final-warning.
	events := waitForEvents(t, r, 3)

	if countWhere(events, func(e event) bool { return e.kind == stateChange }) != 1 {
		t.Fatalf("expected exactly 1 stateChange, got %+v", events)
	}
	if countWhere(events, event.isWarning) != 1 {
		t.Fatalf("expected exactly 1 warning publish, got %+v", events)
	}
	if countWhere(events, event.isFinalWarning) != 1 {
		t.Fatalf("expected exactly 1 final-warning publish, got %+v", events)
	}

	// Warning must precede final (same deadline, longer lead fires first).
	var wIdx, fIdx int
	for i, e := range events {
		switch {
		case e.isWarning():
			wIdx = i
		case e.isFinalWarning():
			fIdx = i
		}
	}
	if wIdx > fIdx {
		t.Fatalf("warning must publish before final-warning, got order %+v", events)
	}
}

func TestDismissSuppressesFinalWarning(t *testing.T) {
	r := &fakeRecorder{}
	w := NewWithLeads(80*time.Millisecond, 30*time.Millisecond, r)
	defer w.Close()

	d := time.Now().Add(100 * time.Millisecond)
	_ = w.Update(d)

	// Wait for the warning publish so we know we're inside the warning
	// window, then dismiss before the final timer would fire.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if countWhere(r.snapshot(), event.isWarning) >= 1 {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	if countWhere(r.snapshot(), event.isWarning) < 1 {
		t.Fatalf("warning did not publish in time, events=%+v", r.snapshot())
	}

	w.Dismiss()

	// Now wait past when the final would have fired.
	time.Sleep(120 * time.Millisecond)

	if n := countWhere(r.snapshot(), event.isFinalWarning); n != 0 {
		t.Fatalf("final-warning published after Dismiss(), events=%+v", r.snapshot())
	}
}

func TestDismissResetByNewDeadline(t *testing.T) {
	r := &fakeRecorder{}
	w := NewWithLeads(80*time.Millisecond, 30*time.Millisecond, r)
	defer w.Close()

	first := time.Now().Add(100 * time.Millisecond)
	_ = w.Update(first)

	// Dismiss against the first deadline.
	w.Dismiss()

	// Replace with a fresh deadline before the first's timers complete.
	time.Sleep(10 * time.Millisecond)
	second := time.Now().Add(100 * time.Millisecond)
	_ = w.Update(second)

	// The second cycle must publish a final-warning (the dismiss state
	// did not carry over).
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if countWhere(r.snapshot(), event.isFinalWarning) >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if countWhere(r.snapshot(), event.isFinalWarning) < 1 {
		t.Fatalf("final-warning did not publish on fresh deadline after Dismiss reset, events=%+v", r.snapshot())
	}
}

func TestDismissBeforeUpdateIsNoop(t *testing.T) {
	r := &fakeRecorder{}
	w := NewWithLeads(80*time.Millisecond, 30*time.Millisecond, r)
	defer w.Close()

	// No deadline tracked yet; Dismiss must be a no-op (no panic, no state).
	w.Dismiss()

	d := time.Now().Add(100 * time.Millisecond)
	_ = w.Update(d)

	// Final warning should still publish — Dismiss only acts on the current
	// deadline, and there was none at the time of the call.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if countWhere(r.snapshot(), event.isFinalWarning) >= 1 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("final-warning did not publish after no-op pre-Update Dismiss, events=%+v", r.snapshot())
}

func TestIsLate(t *testing.T) {
	armedFor := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	lead := 2 * time.Minute
	tests := []struct {
		name       string
		now        time.Time
		cutoffLead time.Duration
		want       bool
	}{
		{"before cutoff", armedFor.Add(-3 * time.Minute), lead, false},
		{"at cutoff", armedFor.Add(-lead), lead, true},
		{"after cutoff", armedFor.Add(-time.Minute), lead, true},
		{"zero lead before deadline", armedFor.Add(-time.Second), 0, false},
		{"zero lead at deadline", armedFor, 0, true},
		{"zero lead after deadline", armedFor.Add(time.Second), 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLate(tt.now, armedFor, tt.cutoffLead); got != tt.want {
				t.Fatalf("isLate(%s, %s, %s) = %v, want %v", tt.now, armedFor, tt.cutoffLead, got, tt.want)
			}
		})
	}
}

func TestIsLateIgnoresMonotonicReading(t *testing.T) {
	now := time.Now()
	wallOnly := now.Round(0)
	if isLate(now, wallOnly.Add(time.Second), 0) {
		t.Fatalf("now with monotonic reading must compare as wall clock before a later wall-only deadline")
	}
	if !isLate(now, wallOnly, 0) {
		t.Fatalf("now with monotonic reading must compare as wall clock at an equal wall-only deadline")
	}
}

func TestLateTimerFiring(t *testing.T) {
	tests := []struct {
		name       string
		final      bool
		beforeDl   time.Duration
		wantWarns  int
		wantFinals int
	}{
		{"warning on resume inside window", false, 3 * time.Minute, 1, 0},
		{"warning promoted to final inside final window", false, time.Minute, 0, 1},
		{"warning skipped past deadline", false, -time.Minute, 0, 0},
		{"final on resume before deadline", true, time.Minute, 0, 1},
		{"final skipped past deadline", true, -time.Minute, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &fakeRecorder{}
			w := New(r)
			defer w.Close()

			// The deadline is an hour out so the real timers never fire
			// during the test; the late callback is invoked directly with an
			// injected clock that simulates a resume near the deadline.
			d := time.Now().Add(time.Hour).Round(0)
			w.nowFn = func() time.Time { return d.Add(-tt.beforeDl) }
			if err := w.Update(d); err != nil {
				t.Fatalf("Update: %v", err)
			}

			if tt.final {
				w.fireFinal(d)
			} else {
				w.fire(d)
			}

			events := r.snapshot()
			if got := countWhere(events, event.isWarning); got != tt.wantWarns {
				t.Fatalf("expected %d warning publishes, got %d: %+v", tt.wantWarns, got, events)
			}
			if got := countWhere(events, event.isFinalWarning); got != tt.wantFinals {
				t.Fatalf("expected %d final-warning publishes, got %d: %+v", tt.wantFinals, got, events)
			}
		})
	}
}

func TestPromotedFinalWarningIsNotRepeated(t *testing.T) {
	r := &fakeRecorder{}
	w := New(r)
	defer w.Close()

	d := time.Now().Add(time.Hour).Round(0)
	now := d.Add(-time.Minute)
	w.nowFn = func() time.Time { return now }
	if err := w.Update(d); err != nil {
		t.Fatalf("Update: %v", err)
	}

	w.fire(d)
	// The final timer was suspended too, so it fires even later than the
	// warning timer, here still just before the deadline.
	now = d.Add(-30 * time.Second)
	w.fireFinal(d)

	events := r.snapshot()
	if got := countWhere(events, event.isFinalWarning); got != 1 {
		t.Fatalf("expected exactly 1 final-warning publish, got %d: %+v", got, events)
	}
	if got := countWhere(events, event.isWarning); got != 0 {
		t.Fatalf("expected no regular warning publish, got %d: %+v", got, events)
	}
}

func TestPromotionRespectsDismiss(t *testing.T) {
	r := &fakeRecorder{}
	w := New(r)
	defer w.Close()

	d := time.Now().Add(time.Hour).Round(0)
	w.nowFn = func() time.Time { return d.Add(-time.Minute) }
	if err := w.Update(d); err != nil {
		t.Fatalf("Update: %v", err)
	}

	w.Dismiss()
	w.fire(d)

	events := r.snapshot()
	if got := countWhere(events, func(e event) bool { return e.kind == publish }); got != 0 {
		t.Fatalf("expected no publish after dismiss, got %d: %+v", got, events)
	}
}

func TestPromotionSkippedWhenFinalAlreadyFired(t *testing.T) {
	r := &fakeRecorder{}
	w := New(r)
	defer w.Close()

	// Both timers fall in the past after a long suspend and are dispatched
	// with a zero delay, so the final callback can run before the warning one.
	d := time.Now().Add(time.Hour).Round(0)
	w.nowFn = func() time.Time { return d.Add(-time.Minute) }
	if err := w.Update(d); err != nil {
		t.Fatalf("Update: %v", err)
	}

	w.fireFinal(d)
	w.fire(d)

	events := r.snapshot()
	if got := countWhere(events, event.isFinalWarning); got != 1 {
		t.Fatalf("expected exactly 1 final-warning publish, got %d: %+v", got, events)
	}
	if got := countWhere(events, event.isWarning); got != 0 {
		t.Fatalf("expected no regular warning publish, got %d: %+v", got, events)
	}
}

func TestDeadlineOnlyRecordsDeadlineWithoutWarnings(t *testing.T) {
	r := &fakeRecorder{}
	w := NewDeadlineOnly(r)
	defer w.Close()

	// With the default leads this deadline would otherwise fire both
	// timers on the next tick.
	d := time.Now().Add(50 * time.Millisecond).Round(0)
	if err := w.Update(d); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if got := r.deadline(); !got.Equal(d) {
		t.Fatalf("expected recorder deadline %v, got %v", d, got)
	}

	time.Sleep(100 * time.Millisecond)

	events := r.snapshot()
	if got := countWhere(events, func(e event) bool { return e.kind == publish }); got != 0 {
		t.Fatalf("expected no publish in deadline-only mode, got %d: %+v", got, events)
	}
	if w.timer != nil || w.finalTimer != nil {
		t.Fatal("expected no timers armed in deadline-only mode")
	}
}

func TestDeadlineOnlyStillRejectsOutOfRangeDeadlines(t *testing.T) {
	r := &fakeRecorder{}
	w := NewDeadlineOnly(r)
	defer w.Close()

	if err := w.Update(time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Update: %v", err)
	}

	err := w.Update(time.Now().Add(-maxPastHorizon - time.Hour))
	if !errors.Is(err, ErrDeadlineInPast) {
		t.Fatalf("expected ErrDeadlineInPast, got %v", err)
	}
	if got := r.deadline(); !got.IsZero() {
		t.Fatalf("expected recorder cleared after rejection, got %v", got)
	}
}
