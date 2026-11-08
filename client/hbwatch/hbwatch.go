// Package hbwatch is a local test helper (aligned keepalive test, never push).
// It keeps the wall time of the last inbound frame per service and, on each
// trigger (a received frame or an explicit CheckNow), waits a short grace and
// runs the dead path of every connected service whose wall-clock gap exceeds
// the heartbeat period plus a tolerance. When a heartbeat near the client
// phase triggered the check (a tick), a service with no frame since the
// previous tick is stale already. A heartbeat far from the client phase comes
// from a stream with a wrong server skew; that stream is reconnected so the
// server takes a new skew.
// The gap is measured on the wall clock so time the phone spent asleep counts.
// Enabled by NB_TEST_HB_STALE=1.
package hbwatch

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/testhb"
)

// Service names a watched stream.
type Service string

const (
	Management Service = "management"
	Signal     Service = "signal"
	Relay      Service = "relay"
)

const (
	// ActionProbe and ActionReconnect name the action in the stale log line.
	ActionProbe     = "probe"
	ActionReconnect = "reconnect"

	envEnabled = "NB_TEST_HB_STALE"
	envPeriod  = "NB_TEST_HB_PERIOD_SEC"

	defaultPeriod = 30 * time.Second
	// Grace lets the other heartbeats of the same tick land before a check.
	Grace = 2 * time.Second
	// Tolerance covers server spread and arrival order.
	Tolerance = 3 * time.Second
	// tickWindow is how far from the client phase a heartbeat may arrive and
	// still mark a tick. A heartbeat further off comes from a stream with a
	// wrong server skew and says nothing about the other streams.
	tickWindow = 3 * time.Second
)

const (
	triggerFrame     = "frame"
	triggerOffPhase  = "offphase"
	triggerHeartbeat = "heartbeat"
	triggerWake      = "wake"
)

var triggerRank = map[string]int{triggerFrame: 0, triggerOffPhase: 1, triggerHeartbeat: 2, triggerWake: 3}

// phaseFunc returns the client heartbeat phase and period, ok false if unknown.
type phaseFunc func() (phase, period time.Duration, ok bool)

var services = []Service{Management, Signal, Relay}

// Clock is the time source. Now must return wall time; AfterFunc schedules f.
type Clock interface {
	Now() time.Time
	AfterFunc(d time.Duration, f func())
}

type realClock struct{}

func (realClock) Now() time.Time                      { return time.Now() }
func (realClock) AfterFunc(d time.Duration, f func()) { time.AfterFunc(d, f) }

type service struct {
	last       time.Time
	lastAction time.Time
	// lastReconnect limits off-phase reconnects. A probe does not count: it
	// cannot fix the skew of a late stream that a tick flagged.
	lastReconnect time.Time
	action        func()
	reconnect     func()
	kind          string
	regID         uint64
	// offPhaseReg is the registration that got an off-phase reconnect. The
	// same connection is not reconnected again for being off phase.
	offPhaseReg uint64
}

// Watcher tracks per-service heartbeat wall times. Use New for tests; the
// package functions use a default Watcher built from env.
type Watcher struct {
	clk    Clock
	period time.Duration
	// phaseFn is asked until it knows the phase. Nil means no ticks.
	phaseFn phaseFunc

	mu      sync.Mutex
	svcs    map[Service]*service
	nextID  uint64
	pending bool
	trigger string
	// tick is set when a heartbeat is among the collapsed triggers.
	tick bool
	// triggerAt is when the pending check was triggered. Gaps are measured
	// there, so the grace does not eat into the tolerance.
	triggerAt time.Time

	phaseMu     sync.Mutex
	phaseKnown  bool
	phase       time.Duration
	phasePeriod time.Duration
}

// New returns a Watcher with the given clock and heartbeat period.
func New(clk Clock, period time.Duration) *Watcher {
	w := &Watcher{clk: clk, period: period, svcs: map[Service]*service{}}
	for _, s := range services {
		w.svcs[s] = &service{}
	}
	return w
}

func (w *Watcher) now() time.Time {
	// Round(0) strips the monotonic reading, so differences are wall time.
	return w.clk.Now().Round(0)
}

// Seen records a heartbeat for svc, logs it and triggers a check.
func (w *Watcher) Seen(svc Service) {
	w.seen(svc, true)
}

// Touch records any other inbound frame for svc like a heartbeat, without the
// per-frame info log, and triggers a check.
func (w *Watcher) Touch(svc Service) {
	w.seen(svc, false)
}

func (w *Watcher) seen(svc Service, logIt bool) {
	w.mu.Lock()
	s, ok := w.svcs[svc]
	if !ok {
		w.mu.Unlock()
		return
	}
	now := w.now()
	s.last = now
	w.mu.Unlock()
	if !logIt {
		w.schedule(triggerFrame)
		return
	}
	off, known := w.phaseOffset(now)
	log.Infof("hbwatch: seen svc=%s t=%d off=%d", svc, now.UnixMilli(), off.Milliseconds())
	if known && off >= -tickWindow && off <= tickWindow {
		w.schedule(triggerHeartbeat)
		return
	}
	if known {
		w.reconnectOffPhase(svc, off)
	}
	w.schedule(triggerOffPhase)
}

// reconnectOffPhase runs the reconnect of svc once per connection, at most
// one reconnect per period.
func (w *Watcher) reconnectOffPhase(svc Service, off time.Duration) {
	w.mu.Lock()
	s := w.svcs[svc]
	now := w.now()
	if s.reconnect == nil || s.offPhaseReg == s.regID ||
		!s.lastReconnect.IsZero() && now.Sub(s.lastReconnect) < w.period-Tolerance {
		w.mu.Unlock()
		return
	}
	s.lastAction = now
	s.lastReconnect = now
	s.offPhaseReg = s.regID
	reconnect := s.reconnect
	w.mu.Unlock()

	log.Infof("hbwatch: offphase svc=%s off=%d action=%s", svc, off.Milliseconds(), ActionReconnect)
	reconnect()
}

// phaseOffset returns how far t is from the nearest client phase, in
// (-period/2, period/2]. known is false while the phase is unknown.
func (w *Watcher) phaseOffset(t time.Time) (off time.Duration, known bool) {
	w.phaseMu.Lock()
	defer w.phaseMu.Unlock()
	if !w.phaseKnown {
		if w.phaseFn == nil {
			return 0, false
		}
		phase, period, ok := w.phaseFn()
		if !ok || period <= 0 {
			return 0, false
		}
		w.phase, w.phasePeriod, w.phaseKnown = phase, period, true
	}
	p := w.phasePeriod.Milliseconds()
	o := ((t.UnixMilli()-w.phase.Milliseconds())%p + p) % p
	if o > p/2 {
		o -= p
	}
	return time.Duration(o) * time.Millisecond, true
}

// CheckNow triggers a check after the grace, for a device wake.
func (w *Watcher) CheckNow() {
	w.schedule(triggerWake)
}

// schedule starts one grace timer; triggers that land while it is pending
// collapse into that check. The log label keeps the highest of wake,
// heartbeat, frame.
func (w *Watcher) schedule(trigger string) {
	w.mu.Lock()
	if w.pending {
		if triggerRank[trigger] > triggerRank[w.trigger] {
			w.trigger = trigger
		}
		w.tick = w.tick || trigger == triggerHeartbeat
		w.mu.Unlock()
		return
	}
	w.pending = true
	w.trigger = trigger
	w.tick = trigger == triggerHeartbeat
	w.triggerAt = w.now()
	w.mu.Unlock()
	w.clk.AfterFunc(Grace, w.check)
}

// Register marks svc connected with its dead-path action and its reconnect
// for an off-phase heartbeat, and resets its timestamp, so a fresh stream is
// not stale. The returned func unregisters it, and is a no-op once a newer
// Register for svc happened.
func (w *Watcher) Register(svc Service, kind string, action, reconnect func()) (unregister func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	s, ok := w.svcs[svc]
	if !ok {
		return func() {}
	}
	w.nextID++
	id := w.nextID
	s.regID = id
	s.action = action
	s.reconnect = reconnect
	s.kind = kind
	s.last = w.now()
	return func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if s.regID == id {
			s.action = nil
			s.reconnect = nil
		}
	}
}

// Reset sets the last heartbeat of svc to now.
func (w *Watcher) Reset(svc Service) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if s, ok := w.svcs[svc]; ok {
		s.last = w.now()
	}
}

func (w *Watcher) check() {
	w.mu.Lock()
	w.pending = false
	trigger := w.trigger
	tick := w.tick
	at := w.triggerAt
	now := w.now()
	limit := w.period + Tolerance
	if tick {
		// The heartbeat of another service marks the tick. A service with no
		// frame since the previous tick missed this one.
		limit = w.period / 2
	}

	gaps := make([]string, 0, len(services))
	type fire struct {
		svc    Service
		kind   string
		gap    time.Duration
		action func()
	}
	var fires []fire
	for _, name := range services {
		s := w.svcs[name]
		if s.action == nil {
			gaps = append(gaps, string(name)+":-1")
			continue
		}
		// A frame that landed during the grace counts as no gap.
		gap := max(at.Sub(s.last), 0)
		gaps = append(gaps, fmt.Sprintf("%s:%d", name, gap.Milliseconds()))
		if gap <= limit {
			continue
		}
		// One action per period. Tick arrival jitters, so the next tick may
		// come a little under one period after the last action.
		if !s.lastAction.IsZero() && now.Sub(s.lastAction) < w.period-Tolerance {
			continue
		}
		s.lastAction = now
		if s.kind == ActionReconnect {
			s.lastReconnect = now
		}
		fires = append(fires, fire{svc: name, kind: s.kind, gap: gap, action: s.action})
	}
	w.mu.Unlock()

	log.Infof("hbwatch: check trigger=%s gaps=%s tick=%t", trigger, strings.Join(gaps, ","), tick)
	for _, f := range fires {
		log.Infof("hbwatch: stale svc=%s gap=%d action=%s", f.svc, f.gap.Milliseconds(), f.kind)
		f.action()
	}
}

// LogProbe logs the outcome of a stale probe.
func LogProbe(svc Service, ok bool, after time.Duration) {
	res := "timeout"
	if ok {
		res = "ok"
	}
	log.Infof("hbwatch: probe svc=%s %s after=%d", svc, res, after.Milliseconds())
}

var (
	defaultMu      sync.Mutex
	defaultSet     atomic.Bool
	defaultWatcher atomic.Pointer[Watcher]
)

// def returns the default Watcher, or nil when NB_TEST_HB_STALE is not 1.
// A disabled result is not kept: the extension can call in (wake, path
// update) before the engine exports the env, and a later call must still
// see the knob.
func def() *Watcher {
	if w := defaultWatcher.Load(); w != nil || defaultSet.Load() {
		return w
	}
	if !enabledFromEnv() {
		return nil
	}
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if w := defaultWatcher.Load(); w != nil || defaultSet.Load() {
		return w
	}
	period := PeriodFromEnv()
	log.Infof("hbwatch: enabled period=%s grace=%s tolerance=%s", period, Grace, Tolerance)
	w := New(realClock{}, period)
	w.phaseFn = testhb.ClientPhase
	defaultWatcher.Store(w)
	return w
}

func enabledFromEnv() bool {
	val := os.Getenv(envEnabled)
	if val == "" {
		return false
	}
	on, err := strconv.ParseBool(val)
	if err != nil {
		log.Warnf("failed to parse %s: %v", envEnabled, err)
		return false
	}
	return on
}

// SetDefault replaces the default Watcher, for tests in packages that call the
// package functions. The returned func restores the previous one.
func SetDefault(w *Watcher) (restore func()) {
	defaultMu.Lock()
	defer defaultMu.Unlock()
	prevSet := defaultSet.Swap(true)
	prev := defaultWatcher.Swap(w)
	return func() {
		defaultMu.Lock()
		defer defaultMu.Unlock()
		defaultWatcher.Store(prev)
		defaultSet.Store(prevSet)
	}
}

// Enabled reports whether NB_TEST_HB_STALE=1.
func Enabled() bool { return def() != nil }

// PeriodFromEnv returns NB_TEST_HB_PERIOD_SEC, default 30 s.
func PeriodFromEnv() time.Duration {
	v, err := strconv.Atoi(os.Getenv(envPeriod))
	if err != nil || v <= 0 {
		return defaultPeriod
	}
	return time.Duration(v) * time.Second
}

// Seen records a heartbeat on the default Watcher. No-op when disabled.
func Seen(svc Service) {
	if w := def(); w != nil {
		w.Seen(svc)
	}
}

// Touch records another inbound frame on the default Watcher. No-op when disabled.
func Touch(svc Service) {
	if w := def(); w != nil {
		w.Touch(svc)
	}
}

// CheckNow triggers a check on the default Watcher. Safe before any service
// registered and after all stopped. No-op when disabled.
func CheckNow() {
	if w := def(); w != nil {
		w.CheckNow()
	}
}

// Register registers svc on the default Watcher. No-op when disabled.
func Register(svc Service, kind string, action, reconnect func()) (unregister func()) {
	if w := def(); w != nil {
		return w.Register(svc, kind, action, reconnect)
	}
	return func() {}
}

// Reset resets svc on the default Watcher. No-op when disabled.
func Reset(svc Service) {
	if w := def(); w != nil {
		w.Reset(svc)
	}
}
