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
	// setDelay stalls SetSessionExpiresAt, widening the window in which a
	// concurrent evaluation could publish a warning out of order.
	setDelay time.Duration
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
	delay := r.setDelay
	r.mu.Unlock()
	// Stall without the lock held, so a concurrent publish can still record.
	time.Sleep(delay)

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

// testInterval keeps the ticker-driven tests fast; the leads they use are
// in the same millisecond scale.
const testInterval = 2 * time.Millisecond

// newWatcher builds a watcher with the final warning disabled (finalLead=0),
// matching the lead-only behaviour the pre-final-warning tests assume.
func newWatcher(lead time.Duration, r *fakeRecorder) *Watcher {
	return newWatcherWithLeads(lead, 0, r)
}

// newWatcherWithLeads builds a watcher that evaluates on testInterval. The
// interval is set before Update, so the evaluation loop does not exist yet
// and the write cannot race it.
func newWatcherWithLeads(lead, final time.Duration, r StatusRecorder) *Watcher {
	w := NewWithLeads(lead, final, r)
	w.interval = testInterval
	return w
}

// fakeClock is the watcher's wall clock under test. Reads come from the
// evaluation goroutine while the test writes, so both go through the mutex.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock(t time.Time) *fakeClock {
	return &fakeClock{t: t}
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// set jumps the clock, standing in for a resume from suspension or for an
// NTP correction.
func (c *fakeClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// settle waits out a handful of evaluation ticks so a test can assert that
// nothing was published.
func settle() {
	time.Sleep(20 * testInterval)
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
	w := newWatcherWithLeads(80*time.Millisecond, 30*time.Millisecond, r)
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
	w := newWatcherWithLeads(80*time.Millisecond, 30*time.Millisecond, r)
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
	w := newWatcherWithLeads(80*time.Millisecond, 30*time.Millisecond, r)
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
	w := newWatcherWithLeads(80*time.Millisecond, 30*time.Millisecond, r)
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

// The tests below drive the watcher's wall clock directly. The deadline sits
// an hour out in real time and the fake clock jumps, standing in for a device
// that was suspended and resumed somewhere inside — or past — the warning
// windows. The evaluation loop is what reacts to the jump, so these exercise
// the same path production takes on a resume.
func newResumeWatcher(t *testing.T, r *fakeRecorder) (*Watcher, *fakeClock, time.Time) {
	t.Helper()

	w := newWatcherWithLeads(WarningLead, FinalWarningLead, r)
	start := time.Now()
	clock := newFakeClock(start)
	// Set before Update: the evaluation loop does not exist yet.
	w.nowFn = clock.now
	t.Cleanup(w.Close)

	deadline := start.Add(time.Hour).Round(0)
	if err := w.Update(deadline); err != nil {
		t.Fatalf("Update: %v", err)
	}
	return w, clock, deadline
}

func TestResumeInsideWarningWindowWarns(t *testing.T) {
	r := &fakeRecorder{}
	_, clock, deadline := newResumeWatcher(t, r)

	clock.set(deadline.Add(-5 * time.Minute))

	events := waitForEvents(t, r, 2)
	if !events[1].isWarning() {
		t.Fatalf("expected the interactive warning after the resume, got %+v", events[1])
	}
	if n := countWhere(events, event.isFinalWarning); n != 0 {
		t.Fatalf("final-warning must wait for its own window, got %d: %+v", n, events)
	}
}

func TestResumeInsideFinalWindowSendsFinalWarningOnly(t *testing.T) {
	r := &fakeRecorder{}
	_, clock, deadline := newResumeWatcher(t, r)

	clock.set(deadline.Add(-time.Minute))

	events := waitForEvents(t, r, 2)
	if !events[1].isFinalWarning() {
		t.Fatalf("expected the final warning after the resume, got %+v", events[1])
	}
	settle()
	if n := countWhere(r.snapshot(), event.isWarning); n != 0 {
		t.Fatalf("the interactive warning is stale inside the final window, got %d: %+v", n, r.snapshot())
	}
}

func TestResumePastDeadlinePublishesNothing(t *testing.T) {
	r := &fakeRecorder{}
	_, clock, deadline := newResumeWatcher(t, r)

	clock.set(deadline.Add(time.Minute))

	settle()
	if n := countWhere(r.snapshot(), func(e event) bool { return e.kind == publish }); n != 0 {
		t.Fatalf("an expired session must not warn, got %d publishes: %+v", n, r.snapshot())
	}
}

func TestWarningPublishesOncePerDeadline(t *testing.T) {
	r := &fakeRecorder{}
	_, clock, deadline := newResumeWatcher(t, r)

	clock.set(deadline.Add(-5 * time.Minute))
	waitForEvents(t, r, 2)

	// Many ticks pass inside the same window.
	settle()
	if n := countWhere(r.snapshot(), event.isWarning); n != 1 {
		t.Fatalf("expected exactly 1 warning publish across ticks, got %d: %+v", n, r.snapshot())
	}
}

// TestWarningRecoversFromAClockRunningAhead covers the device that boots
// before NTP has corrected it: the deadline looks long gone, nothing is
// published, and the warning still arrives once the clock is fixed.
func TestWarningRecoversFromAClockRunningAhead(t *testing.T) {
	r := &fakeRecorder{}
	_, clock, deadline := newResumeWatcher(t, r)

	clock.set(deadline.Add(2 * time.Hour))
	settle()
	if n := countWhere(r.snapshot(), func(e event) bool { return e.kind == publish }); n != 0 {
		t.Fatalf("a deadline that looks expired must not warn, got %d publishes: %+v", n, r.snapshot())
	}

	clock.set(deadline.Add(-5 * time.Minute))

	events := waitForEvents(t, r, 2)
	if !events[1].isWarning() {
		t.Fatalf("expected the warning once the clock was corrected, got %+v", events[1])
	}
}

func TestResumeInsideFinalWindowRespectsDismiss(t *testing.T) {
	r := &fakeRecorder{}
	w, clock, deadline := newResumeWatcher(t, r)

	// The user dismissed the warning for this deadline before the device
	// was suspended; resuming inside the final window must not reopen it.
	w.Dismiss()
	clock.set(deadline.Add(-time.Minute))

	settle()
	if n := countWhere(r.snapshot(), func(e event) bool { return e.kind == publish }); n != 0 {
		t.Fatalf("a dismissed deadline must not warn on resume, got %d: %+v", n, r.snapshot())
	}
}

func TestCloseStopsTheEvaluationLoop(t *testing.T) {
	r := &fakeRecorder{}
	w := newWatcherWithLeads(WarningLead, FinalWarningLead, r)
	start := time.Now()
	clock := newFakeClock(start)
	w.nowFn = clock.now

	deadline := start.Add(time.Hour).Round(0)
	if err := w.Update(deadline); err != nil {
		t.Fatalf("Update: %v", err)
	}
	w.Close()

	clock.set(deadline.Add(-5 * time.Minute))
	settle()

	if n := countWhere(r.snapshot(), func(e event) bool { return e.kind == publish }); n != 0 {
		t.Fatalf("a closed watcher must not publish, got %d: %+v", n, r.snapshot())
	}
}

func TestDeadlineOnlyRecordsDeadlineWithoutWarnings(t *testing.T) {
	r := &fakeRecorder{}
	w := NewDeadlineOnly(r)
	defer w.Close()

	// With the default leads this deadline sits inside the final-warning
	// window, so a watcher that warns at all would publish on the spot.
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
	w.mu.Lock()
	polling := w.stop != nil
	w.mu.Unlock()
	if polling {
		t.Fatal("expected no evaluation loop in deadline-only mode")
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

// TestClockAheadAtUpdateStillWarnsOnceCorrected covers a client that connects
// while its clock runs ahead of real time: the deadline reads as already
// expired when it arrives, so nothing publishes, and the warning must still
// come once NTP pulls the clock back.
func TestClockAheadAtUpdateStillWarnsOnceCorrected(t *testing.T) {
	r := &fakeRecorder{}
	w := newWatcherWithLeads(WarningLead, FinalWarningLead, r)
	deadline := time.Now().Add(time.Hour).Round(0)
	// Two hours past the deadline from the device's point of view, well
	// inside maxPastHorizon, so Update accepts and records it.
	clock := newFakeClock(deadline.Add(2 * time.Hour))
	w.nowFn = clock.now
	t.Cleanup(w.Close)

	if err := w.Update(deadline); err != nil {
		t.Fatalf("Update: %v", err)
	}

	settle()
	if n := countWhere(r.snapshot(), func(e event) bool { return e.kind == publish }); n != 0 {
		t.Fatalf("a deadline that reads as expired must not warn, got %d: %+v", n, r.snapshot())
	}

	clock.set(deadline.Add(-5 * time.Minute))

	events := waitForEvents(t, r, 2)
	if !events[1].isWarning() {
		t.Fatalf("expected the warning once the clock was corrected, got %+v", events[1])
	}
}

// TestWarningNeverPrecedesTheDeadlineStateChange pins the ordering Update
// documents: consumers learn the new deadline before they see a warning that
// refers to it. The deadline here already sits inside the warning window, and
// the recorder stalls, so the evaluation loop gets many chances to publish
// while Update is still announcing.
func TestWarningNeverPrecedesTheDeadlineStateChange(t *testing.T) {
	r := &fakeRecorder{setDelay: 50 * time.Millisecond}
	w := newWatcherWithLeads(WarningLead, FinalWarningLead, r)
	deadline := time.Now().Add(time.Hour).Round(0)
	clock := newFakeClock(deadline.Add(-5 * time.Minute))
	w.nowFn = clock.now
	t.Cleanup(w.Close)

	if err := w.Update(deadline); err != nil {
		t.Fatalf("Update: %v", err)
	}

	events := waitForEvents(t, r, 2)
	if events[0].kind != stateChange {
		t.Fatalf("event[0] should be the deadline state change, got %+v", events)
	}
	if !events[1].isWarning() {
		t.Fatalf("event[1] should be the warning, got %+v", events)
	}
}

// TestUpdateWakesTheLoopWithoutWaitingForATick pins the hand-off: Update
// publishes nothing itself, it nudges the evaluation loop, so a deadline that
// already sits inside a warning window is warned about at once even though the
// ticker here would not fire for an hour.
func TestUpdateWakesTheLoopWithoutWaitingForATick(t *testing.T) {
	r := &fakeRecorder{}
	w := newWatcherWithLeads(WarningLead, FinalWarningLead, r)
	w.interval = time.Hour
	t.Cleanup(w.Close)

	d := time.Now().Add(5 * time.Minute).Round(0)
	if err := w.Update(d); err != nil {
		t.Fatalf("Update: %v", err)
	}

	events := waitForEvents(t, r, 2)
	if !events[1].isWarning() {
		t.Fatalf("expected the warning on the wake-up, got %+v", events[1])
	}
}

// blockingRecorder holds a publish open until the test releases it, so the
// evaluation loop can be parked mid-publish while Close is called.
type blockingRecorder struct {
	fakeRecorder
	entered chan struct{}
	release chan struct{}
}

func (r *blockingRecorder) PublishEvent(
	severity cProto.SystemEvent_Severity,
	category cProto.SystemEvent_Category,
	message string,
	userMessage string,
	metadata map[string]string,
) {
	select {
	case r.entered <- struct{}{}:
	default:
	}
	<-r.release
	r.fakeRecorder.PublishEvent(severity, category, message, userMessage, metadata)
}

// TestConcurrentCloseWaitsForTheLoop pins the contract for the caller that
// loses the race: Close returns only once the loop is done, whichever of the
// two calls got there first.
func TestConcurrentCloseWaitsForTheLoop(t *testing.T) {
	r := &blockingRecorder{entered: make(chan struct{}, 1), release: make(chan struct{})}
	w := newWatcherWithLeads(WarningLead, FinalWarningLead, r)
	w.interval = time.Hour

	d := time.Now().Add(5 * time.Minute).Round(0)
	if err := w.Update(d); err != nil {
		t.Fatalf("Update: %v", err)
	}

	// The loop is now parked inside the warning publish.
	select {
	case <-r.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("the loop never reached the publish")
	}

	first := make(chan struct{})
	second := make(chan struct{})
	go func() { w.Close(); close(first) }()
	go func() { w.Close(); close(second) }()

	select {
	case <-first:
		t.Fatal("Close returned while the loop was still publishing")
	case <-second:
		t.Fatal("Close returned while the loop was still publishing")
	case <-time.After(100 * time.Millisecond):
	}

	close(r.release)
	for _, done := range []chan struct{}{first, second} {
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Close did not return after the publish completed")
		}
	}
}
