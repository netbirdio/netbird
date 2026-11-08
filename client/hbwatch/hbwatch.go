// Package hbwatch is a local test helper (aligned keepalive test, never push).
// It keeps the wall time of the last inbound frame per service and, on each
// trigger (a received frame or an explicit CheckNow), waits a short grace and
// runs the dead path of every connected service whose wall-clock gap exceeds
// the heartbeat period plus a tolerance. The gap is measured on the wall clock
// so time the phone spent asleep counts. Enabled by NB_TEST_HB_STALE=1.
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
)

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
	action     func()
	kind       string
	regID      uint64
}

// Watcher tracks per-service heartbeat wall times. Use New for tests; the
// package functions use a default Watcher built from env.
type Watcher struct {
	clk    Clock
	period time.Duration

	mu      sync.Mutex
	svcs    map[Service]*service
	nextID  uint64
	pending bool
	trigger string
	// triggerAt is when the pending check was triggered. Gaps are measured
	// there, so the grace does not eat into the tolerance.
	triggerAt time.Time
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
	if logIt {
		log.Infof("hbwatch: seen svc=%s t=%d", svc, now.UnixMilli())
	}
	w.schedule("heartbeat")
}

// CheckNow triggers a check after the grace, for a device wake.
func (w *Watcher) CheckNow() {
	w.schedule("wake")
}

// schedule starts one grace timer; triggers that land while it is pending
// collapse into that check. A wake wins over a heartbeat for the log label.
func (w *Watcher) schedule(trigger string) {
	w.mu.Lock()
	if w.pending {
		if trigger == "wake" {
			w.trigger = trigger
		}
		w.mu.Unlock()
		return
	}
	w.pending = true
	w.trigger = trigger
	w.triggerAt = w.now()
	w.mu.Unlock()
	w.clk.AfterFunc(Grace, w.check)
}

// Register marks svc connected with its dead-path action and resets its
// timestamp, so a fresh stream is not stale. The returned func unregisters it,
// and is a no-op once a newer Register for svc happened.
func (w *Watcher) Register(svc Service, kind string, action func()) (unregister func()) {
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
	s.kind = kind
	s.last = w.now()
	return func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if s.regID == id {
			s.action = nil
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
	at := w.triggerAt
	now := w.now()
	limit := w.period + Tolerance

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
		if !s.lastAction.IsZero() && now.Sub(s.lastAction) < w.period {
			continue
		}
		s.lastAction = now
		fires = append(fires, fire{svc: name, kind: s.kind, gap: gap, action: s.action})
	}
	w.mu.Unlock()

	log.Infof("hbwatch: check trigger=%s gaps=%s", trigger, strings.Join(gaps, ","))
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
	defaultOnce    sync.Once
	defaultWatcher atomic.Pointer[Watcher]
)

// def returns the default Watcher, or nil when NB_TEST_HB_STALE is not 1.
func def() *Watcher {
	defaultOnce.Do(func() {
		if !enabledFromEnv() {
			return
		}
		period := PeriodFromEnv()
		log.Infof("hbwatch: enabled period=%s grace=%s tolerance=%s", period, Grace, Tolerance)
		defaultWatcher.Store(New(realClock{}, period))
	})
	return defaultWatcher.Load()
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
	defaultOnce.Do(func() {})
	prev := defaultWatcher.Swap(w)
	return func() { defaultWatcher.Store(prev) }
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
func Register(svc Service, kind string, action func()) (unregister func()) {
	if w := def(); w != nil {
		return w.Register(svc, kind, action)
	}
	return func() {}
}

// Reset resets svc on the default Watcher. No-op when disabled.
func Reset(svc Service) {
	if w := def(); w != nil {
		w.Reset(svc)
	}
}
