// Package sessionwatch tracks the SSO session expiry deadline that the
// management server publishes via LoginResponse / SyncResponse and fires
// two warning events at fixed lead times before expiry: an interactive
// T-WarningLead notification and a dismiss-gated T-FinalWarningLead
// fallback dialog.
//
// The watcher is idempotent: Update may be called as often as the network
// map snapshots arrive. Repeating the same deadline is a no-op; a new
// deadline reschedules the timers and arms a fresh warning cycle.
//
// Warning firing is edge-detected. Each unique deadline value fires each
// warning callback at most once.
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
	// glitch, and silently arming a 100-year timer would hide the bug.
	maxDeadlineHorizon = 10 * 365 * 24 * time.Hour

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
	lead      time.Duration
	finalLead time.Duration

	mu           sync.Mutex
	current      time.Time
	timer        *time.Timer
	finalTimer   *time.Timer
	firedAt      time.Time // deadline value the T-WarningLead callback last fired against
	finalFiredAt time.Time // deadline value the T-FinalWarningLead callback last fired against
	dismissedAt  time.Time // deadline value the user dismissed via Dismiss(); gates fireFinal
	closed       bool
	recorder     StatusRecorder
}

// New returns a watcher with the package defaults WarningLead and
// FinalWarningLead. Pass nil for recorder to silence side effects (handy
// in unit tests that exercise sanity checks without observing the publish
// path).
func New(recorder StatusRecorder) *Watcher {
	return NewWithLeads(WarningLead, FinalWarningLead, recorder)
}

// NewWithLeads returns a watcher with custom lead times. Useful for tests.
// final must be strictly less than lead; otherwise both timers fire in the
// wrong order or simultaneously and the UI flow breaks. A zero final lead
// disables the final-warning timer entirely (see armTimerLocked) so a
// millisecond-scale deadline doesn't flush both timers in one tick.
func NewWithLeads(lead, final time.Duration, recorder StatusRecorder) *Watcher {
	return &Watcher{
		lead:      lead,
		finalLead: final,
		recorder:  recorder,
	}
}

// Update sets the latest deadline. Pass the zero time to clear (e.g. when
// a Sync push from the server omits the field because login expiration
// was disabled).
//
// Same-value updates are no-ops. A different non-zero value cancels any
// pending timer, resets the "already fired" guards, and — when the
// deadline lies in the future — arms fresh warning timers. A deadline
// already in the past (within maxPastHorizon) is recorded as-is with no
// timers: the session has expired and consumers render it that way.
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

	w.stopTimerLocked()
	w.current = deadline
	// Reset every per-deadline guard so a refreshed deadline arms a fresh
	// warning cycle: both edge triggers and the user Dismiss decision
	// (the user agreed to the old deadline expiring; a new deadline
	// restarts the contract).
	w.firedAt = time.Time{}
	w.finalFiredAt = time.Time{}
	w.dismissedAt = time.Time{}

	if deadline.After(now) {
		w.armTimerLocked(deadline)
	}
	recorder := w.recorder
	w.mu.Unlock()
	if recorder != nil {
		recorder.SetSessionExpiresAt(deadline)
	}
	log.Infof("auth session deadline set to: %s (in %s)", deadline.Format(time.RFC3339), time.Until(deadline).Round(time.Second))
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
// and suppresses the upcoming final-warning callback for that deadline.
// Idempotent: repeated calls are no-ops. A subsequent Update with a fresh
// deadline resets the dismissal so the final-warning cycle re-arms.
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
	// Cancel the armed final-warning timer eagerly. fireFinal would also
	// gate on dismissedAt, but stopping the timer avoids a wakeup with
	// nothing to do and makes the intent visible.
	if w.finalTimer != nil {
		w.finalTimer.Stop()
		w.finalTimer = nil
	}
	log.Infof("auth session final-warning dismissed for deadline %s", w.current.Format(time.RFC3339))
}

// Close stops any pending timer. Update calls after Close are ignored.
// The recorder keeps its deadline: the watcher is engine-scoped and closes
// on every engine restart (network change, sleep/wake, stream errors)
// while the SSO deadline stays valid across those, so clearing here would
// blank the UI's "expires in" row on every transient reconnect. The
// client run loop clears the server-scoped recorder when it exits for
// real (Down, profile switch, permanent login failure).
func (w *Watcher) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.closed = true
	w.stopTimerLocked()
	w.current = time.Time{}
	w.firedAt = time.Time{}
	w.finalFiredAt = time.Time{}
	w.dismissedAt = time.Time{}
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
	w.stopTimerLocked()
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

func (w *Watcher) stopTimerLocked() {
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
	if w.finalTimer != nil {
		w.finalTimer.Stop()
		w.finalTimer = nil
	}
}

func (w *Watcher) armTimerLocked(deadline time.Time) {
	w.timer = armOneShotLocked(deadline.Add(-w.lead), func() { w.fire(deadline) })
	// finalLead <= 0 disables the final-warning timer entirely. Used by
	// tests that predate the final-warning fallback so a millisecond-scale
	// deadline does not flush both timers at once.
	if w.finalLead > 0 {
		w.finalTimer = armOneShotLocked(deadline.Add(-w.finalLead), func() { w.fireFinal(deadline) })
	}
}

func (w *Watcher) fire(armedFor time.Time) {
	w.mu.Lock()
	if w.closed || !w.current.Equal(armedFor) {
		// Deadline moved while we were waiting (e.g. a successful extend).
		// The reschedule path armed a fresh timer; this one is stale.
		w.mu.Unlock()
		return
	}
	if !w.firedAt.IsZero() && w.firedAt.Equal(armedFor) {
		w.mu.Unlock()
		return
	}
	w.firedAt = armedFor
	recorder := w.recorder
	w.mu.Unlock()
	if recorder == nil {
		return
	}
	log.Infof("auth session expiry soon warning fired")
	publishWarning(recorder, armedFor, false)
}

// fireFinal mirrors fire for the T-FinalWarningLead timer with an extra
// dismiss-gate: if the user dismissed the T-WarningLead notification for
// this deadline, the final warning is suppressed entirely.
func (w *Watcher) fireFinal(armedFor time.Time) {
	w.mu.Lock()
	if w.closed || !w.current.Equal(armedFor) {
		w.mu.Unlock()
		return
	}
	if !w.finalFiredAt.IsZero() && w.finalFiredAt.Equal(armedFor) {
		w.mu.Unlock()
		return
	}
	if w.dismissedAt.Equal(armedFor) {
		w.mu.Unlock()
		log.Infof("auth session final-warning skipped (dismissed by user)")
		return
	}
	w.finalFiredAt = armedFor
	recorder := w.recorder
	w.mu.Unlock()
	if recorder == nil {
		return
	}
	log.Infof("auth session final-warning fired")
	publishWarning(recorder, armedFor, true)
}

// armOneShotLocked schedules cb at fireAt. When fireAt is already in the
// past it dispatches on the next scheduler tick so a state-change recorder
// notification (invoked after w.mu is released) lands first. Caller must
// hold w.mu.
func armOneShotLocked(fireAt time.Time, cb func()) *time.Timer {
	delay := time.Until(fireAt)
	if delay <= 0 {
		return time.AfterFunc(0, cb)
	}
	return time.AfterFunc(delay, cb)
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
