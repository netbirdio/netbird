// Package sessionwatch tracks the SSO session expiry deadline that the
// management server publishes via LoginResponse / SyncResponse and fires
// two warning events at fixed lead times before expiry: an interactive
// T-WarningLead notification and a dismiss-gated T-FinalWarningLead
// fallback dialog.
//
// The deadline is an absolute wall-clock instant, so the watcher compares
// it against the wall clock on a ticker rather than arming a relative
// timer for it. A relative timer runs on the monotonic clock, which does
// not advance while a device is suspended: it fires once that much awake
// time has passed, which can be long after the deadline, and nothing
// re-evaluates when the device wakes up. Polling makes every tick after a
// resume (or after an NTP correction) see the real remaining time.
//
// The watcher is idempotent: Update may be called as often as the network
// map snapshots arrive. Repeating the same deadline is a no-op; a new
// deadline starts a fresh warning cycle.
//
// Warning firing is edge-detected. Each unique deadline value publishes
// each warning at most once.
package sessionwatch

import (
	"errors"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	cProto "github.com/netbirdio/netbird/client/proto"
)

const (
	maxPastHorizon = 30 * 24 * time.Hour

	// maxDeadlineHorizon caps how far in the future an accepted deadline
	// can sit. A timestamp beyond this is almost certainly a protocol
	// glitch, and silently tracking a 100-year deadline would hide the bug.
	maxDeadlineHorizon = 10 * 365 * 24 * time.Hour

	// defaultEvalInterval is how often the tracked deadline is compared
	// against the wall clock. The leads are minutes, so a coarse tick costs
	// nothing in accuracy and keeps the wakeup cheap on battery-powered
	// devices.
	defaultEvalInterval = 10 * time.Second

	// WarningLead is how far before expiry the first (interactive)
	// warning fires. Drives the T-10 OS notification with
	// Extend/Dismiss actions.
	WarningLead = 10 * time.Minute

	// FinalWarningLead is how far before expiry the fallback final
	// warning fires. Drives the auto-opened SessionAboutToExpire dialog,
	// but only when the user has not dismissed the T-WarningLead warning
	// for the same deadline. Must be strictly less than WarningLead.
	FinalWarningLead = 2 * time.Minute
)

var (
	// ErrDeadlineBeforeEpoch is returned by Update when the supplied
	// deadline pre-dates 1970-01-01.
	ErrDeadlineBeforeEpoch = errors.New("session deadline before unix epoch")

	// ErrDeadlineTooFarFuture is returned by Update when the supplied
	// deadline is more than maxDeadlineHorizon in the future.
	ErrDeadlineTooFarFuture = errors.New("session deadline too far in the future")

	// ErrDeadlineInPast is returned by Update when the supplied deadline
	// is more than maxPastHorizon in the past.
	ErrDeadlineInPast = errors.New("session deadline in the past")
)

// StatusRecorder is the side-effect surface the watcher drives on every
// state transition. Production wires this to peer.Status (SetSessionExpiresAt
// for deadline change/clear, PublishEvent for the two warnings); tests pass
// a fake recorder so the same surface is observable without an engine.
//
// While the watcher runs, it owns the deadline propagated to the recorder:
// every set, clear and sanity-check rejection routes the value through
// SetSessionExpiresAt, so the SubscribeStatus snapshot the UI reads can
// never drift from the watcher's timer state. (SetSessionExpiresAt fans
// out its own state-change notification, so no separate notify is needed.)
// The recorder is server-scoped and outlives this engine-scoped watcher;
// Close deliberately leaves the recorder value in place so transient engine
// restarts don't blank it — the client run loop clears it on real teardown.
//
// PublishEvent's signature mirrors peer.Status.PublishEvent: the watcher
// composes the metadata internally so the wire format (MetaSession*) is
// owned by sessionwatch, not the caller.
type StatusRecorder interface {
	SetSessionExpiresAt(deadline time.Time)
	PublishEvent(
		severity cProto.SystemEvent_Severity,
		category cProto.SystemEvent_Category,
		message string,
		userMessage string,
		metadata map[string]string,
	)
}

// Watcher observes the latest session deadline and fires two warnings
// before it expires: the interactive T-WarningLead notification, and the
// fallback T-FinalWarningLead dialog (suppressed when the user dismissed
// the first one for the same deadline). Safe for concurrent use.
type Watcher struct {
	lead         time.Duration
	finalLead    time.Duration
	interval     time.Duration
	deadlineOnly bool

	mu           sync.Mutex
	current      time.Time
	firedAt      time.Time // deadline value the T-WarningLead warning last published for
	finalFiredAt time.Time // deadline value the T-FinalWarningLead warning last published for
	dismissedAt  time.Time // deadline value the user dismissed via Dismiss(); gates the final warning
	closed       bool
	recorder     StatusRecorder
	nowFn        func() time.Time
	stop         chan struct{} // closed to stop the evaluation loop; nil while it is not running
	done         chan struct{} // closed by the loop on its way out
}

// New returns a watcher with the package defaults WarningLead and
// FinalWarningLead. Pass nil for recorder to silence side effects (handy
// in unit tests that exercise sanity checks without observing the publish
// path).
func New(recorder StatusRecorder) *Watcher {
	return NewWithLeads(WarningLead, FinalWarningLead, recorder)
}

// NewWithLeads returns a watcher with custom lead times. Useful for tests.
// final must be strictly less than lead; otherwise the final warning takes
// over the whole warning window and the interactive notification never
// shows. A zero final lead disables the final warning entirely (see
// evaluate), leaving the interactive one as the only warning.
func NewWithLeads(lead, final time.Duration, recorder StatusRecorder) *Watcher {
	return &Watcher{
		lead:      lead,
		finalLead: final,
		interval:  defaultEvalInterval,
		recorder:  recorder,
		nowFn:     time.Now,
	}
}

// NewDeadlineOnly returns a watcher that validates and records deadlines but arms no warning timers.
func NewDeadlineOnly(recorder StatusRecorder) *Watcher {
	w := New(recorder)
	w.deadlineOnly = true
	return w
}

// Update sets the latest deadline. Pass the zero time to clear (e.g. when
// a Sync push from the server omits the field because login expiration
// was disabled).
//
// Same-value updates are no-ops. A different non-zero value resets the
// "already fired" guards and starts a fresh warning cycle, evaluated
// immediately so a deadline that already sits inside a warning window
// warns without waiting for the next tick. A deadline already in the past
// (within maxPastHorizon) is recorded as-is and warns nothing: the session
// has expired and consumers render it that way.
//
// Returns one of the sentinel Err* values when the deadline fails the
// sanity checks (pre-epoch, far future, or past beyond maxPastHorizon).
// In every error case the watcher first clears its state so it stays
// consistent with what the caller will push into its other sinks (e.g.
// applySessionDeadline forces a zero deadline into the status recorder
// after a non-nil error).
func (w *Watcher) Update(deadline time.Time) error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return nil
	}

	if deadline.IsZero() {
		w.clearLocked()
		return nil
	}

	now := time.Now()
	switch {
	case deadline.Before(time.Unix(0, 0)):
		w.clearLocked()
		return fmt.Errorf("%w: %v", ErrDeadlineBeforeEpoch, deadline)
	case deadline.After(now.Add(maxDeadlineHorizon)):
		w.clearLocked()
		return fmt.Errorf("%w: %v", ErrDeadlineTooFarFuture, deadline)
	case deadline.Before(now.Add(-maxPastHorizon)):
		w.clearLocked()
		return fmt.Errorf("%w: %v (now=%v)", ErrDeadlineInPast, deadline, now)
	}

	if deadline.Equal(w.current) {
		w.mu.Unlock()
		return nil
	}

	w.current = deadline
	// Reset every per-deadline guard so a refreshed deadline starts a fresh
	// warning cycle: both edge triggers and the user Dismiss decision
	// (the user agreed to the old deadline expiring; a new deadline
	// restarts the contract).
	w.firedAt = time.Time{}
	w.finalFiredAt = time.Time{}
	w.dismissedAt = time.Time{}

	if deadline.After(now) && !w.deadlineOnly {
		w.startPollLocked()
	}
	recorder := w.recorder
	w.mu.Unlock()
	if recorder != nil {
		recorder.SetSessionExpiresAt(deadline)
	}
	log.Infof("auth session deadline set to: %s (in %s)", deadline.Format(time.RFC3339), time.Until(deadline).Round(time.Second))
	// Evaluated after the recorder call so the state change reaches
	// consumers before any warning event that refers to it.
	w.evaluate()
	return nil
}

// Deadline returns the most recently observed deadline. Zero when no
// deadline is currently tracked.
func (w *Watcher) Deadline() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.current
}

// Dismiss records the user's "Dismiss" action against the current deadline
// and suppresses the final warning for that deadline. Idempotent: repeated
// calls are no-ops. A subsequent Update with a fresh deadline resets the
// dismissal so the final-warning cycle starts over.
//
// No-op when the watcher holds no deadline or has been closed.
func (w *Watcher) Dismiss() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed || w.current.IsZero() {
		return
	}
	if w.dismissedAt.Equal(w.current) {
		return
	}
	w.dismissedAt = w.current
	log.Infof("auth session final-warning dismissed for deadline %s", w.current.Format(time.RFC3339))
}

// Close stops the evaluation loop and waits for it to exit. Update calls
// after Close are ignored. The recorder keeps its deadline: the watcher is
// engine-scoped and closes on every engine restart (network change,
// sleep/wake, stream errors) while the SSO deadline stays valid across
// those, so clearing here would blank the UI's "expires in" row on every
// transient reconnect. The client run loop clears the server-scoped
// recorder when it exits for real (Down, profile switch, permanent login
// failure).
func (w *Watcher) Close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	w.current = time.Time{}
	w.firedAt = time.Time{}
	w.finalFiredAt = time.Time{}
	w.dismissedAt = time.Time{}
	// Copy the channels out and drop them before releasing the lock: the
	// loop takes w.mu on every tick, so waiting for it while holding the
	// lock would deadlock.
	stop, done := w.stop, w.done
	w.stop, w.done = nil, nil
	w.mu.Unlock()

	if stop == nil {
		return
	}
	close(stop)
	<-done
}

// clearLocked drops the tracked deadline and notifies the recorder so
// downstream consumers (SubscribeStatus stream, UI) drop their anchor.
// The caller must hold w.mu; this helper releases it before invoking
// the recorder.
func (w *Watcher) clearLocked() {
	if w.current.IsZero() {
		w.mu.Unlock()
		return
	}
	w.current = time.Time{}
	w.firedAt = time.Time{}
	w.finalFiredAt = time.Time{}
	w.dismissedAt = time.Time{}
	recorder := w.recorder
	w.mu.Unlock()
	if recorder != nil {
		recorder.SetSessionExpiresAt(time.Time{})
	}
	log.Infof("auth session deadline cleared")
}

// startPollLocked starts the evaluation loop unless it is already
// running. The loop starts lazily on the first future deadline, so a
// client whose server never publishes a session expiry never pays for a
// ticker, and it runs until Close: the watcher is engine-scoped, and a
// cleared deadline is normally followed by a fresh one on the next sync.
// Caller must hold w.mu.
func (w *Watcher) startPollLocked() {
	if w.stop != nil {
		return
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	w.stop, w.done = stop, done
	go w.poll(stop, done, w.interval)
}

// poll re-evaluates the tracked deadline every interval. Its channels and
// interval are passed in rather than read off the receiver, so Close can
// clear them without racing the goroutine.
func (w *Watcher) poll(stop <-chan struct{}, done chan<- struct{}, interval time.Duration) {
	defer close(done)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			w.evaluate()
		}
	}
}

// evaluate compares the tracked deadline against the wall clock and
// publishes whichever warning the remaining time calls for. Inside the
// final-warning window the interactive warning is stale, so the final one
// is published in its place: a device that resumes there never saw the
// T-WarningLead notification.
func (w *Watcher) evaluate() {
	w.mu.Lock()
	if w.closed || w.deadlineOnly || w.current.IsZero() {
		w.mu.Unlock()
		return
	}

	deadline := w.current
	// Round(0) strips the monotonic reading so the comparison is wall
	// clock on both sides, whether the deadline came off the wire or from
	// a caller that derived it from time.Now.
	remaining := deadline.Round(0).Sub(w.nowFn().Round(0))

	switch {
	case remaining <= 0:
		// Already expired: the post-mortem SessionExpired flow owns it.
		w.mu.Unlock()
	case w.finalLead > 0 && remaining <= w.finalLead:
		w.publishFinalLocked(deadline, remaining)
	case remaining <= w.lead:
		w.publishWarningLocked(deadline, remaining)
	default:
		w.mu.Unlock()
	}
}

// publishWarningLocked emits the interactive T-WarningLead warning, at
// most once per deadline value. Caller must hold w.mu; this helper
// releases it.
func (w *Watcher) publishWarningLocked(deadline time.Time, remaining time.Duration) {
	if w.firedAt.Equal(deadline) {
		w.mu.Unlock()
		return
	}
	w.firedAt = deadline
	recorder := w.recorder
	w.mu.Unlock()
	if recorder == nil {
		return
	}
	log.Infof("auth session expiry soon warning fired for deadline %s (in %s)",
		deadline.Format(time.RFC3339), remaining.Round(time.Second))
	publishWarning(recorder, deadline, false)
}

// publishFinalLocked emits the final warning, at most once per deadline
// value and never once the user dismissed that deadline. It marks the
// interactive warning as handled too: the final window is open, so a
// "expires in WarningLead minutes" notification would be wrong. Caller
// must hold w.mu; this helper releases it.
func (w *Watcher) publishFinalLocked(deadline time.Time, remaining time.Duration) {
	if w.finalFiredAt.Equal(deadline) || w.dismissedAt.Equal(deadline) {
		w.mu.Unlock()
		return
	}
	w.firedAt = deadline
	w.finalFiredAt = deadline
	recorder := w.recorder
	w.mu.Unlock()
	if recorder == nil {
		return
	}
	log.Infof("auth session final-warning fired for deadline %s (in %s)",
		deadline.Format(time.RFC3339), remaining.Round(time.Second))
	publishWarning(recorder, deadline, true)
}

// publishWarning composes the SystemEvent for a watcher-fired warning and
// pushes it through the recorder. Severity is CRITICAL on both — bypassing
// the user's Notifications toggle is deliberate: missing the warning
// window forces the post-mortem SessionExpired flow (tunnel torn down,
// lock icon, manual re-login), which is the UX we are trying to avoid.
func publishWarning(recorder StatusRecorder, deadline time.Time, final bool) {
	lead := WarningLead
	message := "session expiry warning"
	meta := map[string]string{
		MetaSessionWarning:   "true",
		MetaSessionExpiresAt: FormatExpiresAt(deadline),
	}
	if final {
		lead = FinalWarningLead
		message = "session expiry final warning"
		meta[MetaSessionFinal] = "true"
	}
	meta[MetaSessionLeadMinutes] = FormatLeadMinutes(lead)

	recorder.PublishEvent(
		cProto.SystemEvent_CRITICAL,
		cProto.SystemEvent_AUTHENTICATION,
		message,
		"",
		meta,
	)
}
