// Package hbwatch is a local test helper (aligned keepalive test, never push).
// It keeps the wall time of the last inbound frame per service and judges
// each service against the heartbeat burst of the others, not against the
// client phase. A test heartbeat that arrives while no burst is open starts
// one; test heartbeats within the burst delay join it, and the burst is
// checked when the delay runs out. In a burst of two or more services a
// registered service that did not join and sent nothing for half a period is
// stale. A service that comes alone, on two lone bursts in a row at the same
// offset from the last full burst, has a wrong server skew and is reconnected
// so the server takes a new skew. Wakes check after a short grace with the
// period plus tolerance rule.
// Gaps are measured on the wall clock so time the phone spent asleep counts.
// No action runs while no Management or Signal test heartbeat came within 2
// periods.
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

	envEnabled    = "NB_TEST_HB_STALE"
	envPeriod     = "NB_TEST_HB_PERIOD_SEC"
	envBurstDelay = "NB_TEST_HB_BURST_DELAY_MS"

	defaultPeriod = 30 * time.Second
	// BurstDelay is how long after the first test heartbeat of a burst the
	// others may join it. Cellular paging plus one TCP resend can delay a
	// healthy heartbeat 3 to 5 s.
	BurstDelay = 5 * time.Second
	// Grace lets the frames of a wake land before its check.
	Grace = 2 * time.Second
	// Tolerance covers arrival jitter on the period rule and the action limit.
	Tolerance = 3 * time.Second
	// lateAfter marks a check whose timer ran this long after its time: the
	// phone slept past it.
	lateAfter = time.Second
	// offBurstMatch is how close the offsets of two lone bursts must be to
	// show one constant wrong skew rather than jitter.
	offBurstMatch = 500 * time.Millisecond
)

const (
	triggerBurst = "burst"
	triggerLone  = "lone"
	triggerWake  = "wake"
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
	reconnect  func()
	kind       string
	regID      uint64
	// offBurstAt is the start of the last lone burst of this service that was
	// off the reference burst, zero when none; offBurst is its offset.
	offBurstAt time.Time
	offBurst   time.Duration
}

func (s *service) clearOffBurst() {
	s.offBurstAt = time.Time{}
	s.offBurst = 0
}

// burst is one group of test heartbeats waiting for its check.
type burst struct {
	gen     uint64
	start   time.Time
	members []Service
}

func (b *burst) has(svc Service) bool {
	for _, m := range b.members {
		if m == svc {
			return true
		}
	}
	return false
}

// Watcher tracks per-service heartbeat wall times. Use New for tests; the
// package functions use a default Watcher built from env.
type Watcher struct {
	clk        Clock
	period     time.Duration
	burstDelay time.Duration

	mu   sync.Mutex
	svcs map[Service]*service
	// lastTestHB is the last Management or Signal heartbeat. Servers send
	// those only in a test mode; the relay health check comes in mode off too.
	lastTestHB time.Time
	nextID     uint64
	// open is the burst waiting for its check, nil when none.
	open     *burst
	burstGen uint64
	// refBurst is the start of the last burst with two or more members.
	refBurst    time.Time
	wakePending bool
	wakeAt      time.Time
}

// New returns a Watcher with the given clock and heartbeat period. The burst
// delay comes from NB_TEST_HB_BURST_DELAY_MS, default BurstDelay.
func New(clk Clock, period time.Duration) *Watcher {
	w := &Watcher{clk: clk, period: period, burstDelay: burstDelayFromEnv(), svcs: map[Service]*service{}}
	for _, s := range services {
		w.svcs[s] = &service{}
	}
	return w
}

func (w *Watcher) now() time.Time {
	// Round(0) strips the monotonic reading, so differences are wall time.
	return w.clk.Now().Round(0)
}

// checkResult holds the log lines and actions of one check, run after the
// lock is released.
type checkResult struct {
	lines   []string
	actions []func()
}

func (r *checkResult) logf(format string, args ...any) {
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}

func (r *checkResult) run() {
	for _, l := range r.lines {
		log.Info(l)
	}
	for _, a := range r.actions {
		a()
	}
}

// Seen records a test heartbeat for svc. It opens a burst when none is open
// and joins the open one otherwise.
func (w *Watcher) Seen(svc Service) {
	w.mu.Lock()
	s, ok := w.svcs[svc]
	if !ok {
		w.mu.Unlock()
		return
	}
	now := w.now()
	// The check of the open burst is due but has not run: the phone slept past
	// its timer, or the timer is about to fire. Settle it before this
	// heartbeat counts.
	var prev checkResult
	if b := w.open; b != nil && now.After(b.start.Add(w.burstDelay)) {
		w.open = nil
		if now.Sub(b.start.Add(w.burstDelay)) > lateAfter {
			prev = w.skipLate(b, now)
		} else {
			prev = w.evalBurst(b, now)
		}
	}
	s.last = now
	if svc != Relay {
		w.lastTestHB = now
	}
	started := w.open == nil
	if started {
		w.burstGen++
		w.open = &burst{gen: w.burstGen, start: now}
	}
	b := w.open
	if !b.has(svc) {
		b.members = append(b.members, svc)
	}
	gen := b.gen
	w.mu.Unlock()

	prev.run()
	log.Infof("hbwatch: seen svc=%s t=%d", svc, now.UnixMilli())
	if started {
		log.Infof("hbwatch: burst start svc=%s t=%d", svc, now.UnixMilli())
		w.clk.AfterFunc(w.burstDelay, func() { w.checkBurst(gen) })
	}
}

// Touch records any other inbound frame for svc. It counts as alive but never
// opens or joins a burst.
func (w *Watcher) Touch(svc Service) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if s, ok := w.svcs[svc]; ok {
		s.last = w.now()
	}
}

// testHBActive reports whether a Management or Signal test heartbeat came
// within 2 periods. Without them the server runs stock (mode off, old server)
// and gaps say nothing. Caller holds w.mu.
func (w *Watcher) testHBActive(now time.Time) bool {
	return !w.lastTestHB.IsZero() && now.Sub(w.lastTestHB) <= 2*w.period
}

// mayAct reports whether s had no action within the last period. Arrival
// jitters, so the next tick may come a little under one period after the last
// action. Caller holds w.mu.
func (w *Watcher) mayAct(s *service, now time.Time) bool {
	return s.lastAction.IsZero() || now.Sub(s.lastAction) >= w.period-Tolerance
}

// centered returns d mod p in (-p/2, p/2].
func centered(d, p time.Duration) time.Duration {
	o := (d%p + p) % p
	if o > p/2 {
		o -= p
	}
	return o
}

func (w *Watcher) checkBurst(gen uint64) {
	w.mu.Lock()
	b := w.open
	if b == nil || b.gen != gen {
		// Settled already by a later heartbeat.
		w.mu.Unlock()
		return
	}
	w.open = nil
	r := w.evalBurst(b, w.now())
	w.mu.Unlock()
	r.run()
}

// gaps formats the gap of every service at t, -1 for one not registered.
// Caller holds w.mu.
func (w *Watcher) gaps(t time.Time) string {
	out := make([]string, 0, len(services))
	for _, name := range services {
		s := w.svcs[name]
		if s.action == nil {
			out = append(out, string(name)+":-1")
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d", name, max(t.Sub(s.last), 0).Milliseconds()))
	}
	return strings.Join(out, ",")
}

func joinMembers(b *burst) string {
	names := make([]string, 0, len(b.members))
	for _, m := range b.members {
		names = append(names, string(m))
	}
	return strings.Join(names, ",")
}

func burstTrigger(b *burst) string {
	if len(b.members) < 2 {
		return triggerLone
	}
	return triggerBurst
}

// skipLate closes a burst whose check the phone slept past, after a newer
// burst opened. The newer burst covers the missing services. Caller holds
// w.mu.
func (w *Watcher) skipLate(b *burst, now time.Time) checkResult {
	var r checkResult
	due := b.start.Add(w.burstDelay)
	r.logf("hbwatch: check trigger=%s members=%s gaps=%s wait=%d late=%d skipped=late",
		burstTrigger(b), joinMembers(b), w.gaps(b.start), now.Sub(b.start).Milliseconds(), now.Sub(due).Milliseconds())
	if len(b.members) >= 2 {
		w.refBurst = b.start
	}
	return r
}

// evalBurst runs the check of burst b at now. Gaps are measured at the burst
// start, so a frame that landed during the burst counts as no gap. Caller
// holds w.mu.
func (w *Watcher) evalBurst(b *burst, now time.Time) checkResult {
	var r checkResult
	at := b.start
	gateOpen := w.testHBActive(now)
	trigger := burstTrigger(b)

	extra := ""
	if late := now.Sub(at.Add(w.burstDelay)); late > lateAfter {
		extra += fmt.Sprintf(" late=%d", late.Milliseconds())
	}
	if !gateOpen {
		extra += " gate=closed"
	}
	r.logf("hbwatch: check trigger=%s members=%s gaps=%s wait=%d%s",
		trigger, joinMembers(b), w.gaps(at), now.Sub(at).Milliseconds(), extra)

	limit := w.period / 2
	if trigger == triggerBurst {
		w.refBurst = at
		for _, m := range b.members {
			w.svcs[m].clearOffBurst()
		}
	} else {
		limit = w.period + Tolerance
		w.judgeLone(b.members[0], at, now, gateOpen, &r)
	}
	for _, name := range services {
		if !b.has(name) {
			w.staleCheck(name, at, limit, now, gateOpen, &r)
		}
	}
	return r
}

// judgeLone handles the only member of a lone burst at at. Off the reference
// burst on two lone bursts in a row at the same offset, the service has a
// wrong server skew and is reconnected. Caller holds w.mu.
func (w *Watcher) judgeLone(svc Service, at, now time.Time, gateOpen bool, r *checkResult) {
	s := w.svcs[svc]
	if w.registered() < 2 || w.refBurst.IsZero() || at.Sub(w.refBurst) > 2*w.period {
		return
	}
	off := centered(at.Sub(w.refBurst), w.period)
	if off.Abs() <= w.burstDelay {
		// On time at the reference burst; the others missed it.
		s.clearOffBurst()
		return
	}
	confirm := !s.offBurstAt.IsZero() && at.Sub(s.offBurstAt) <= w.period*3/2 &&
		centered(off-s.offBurst, w.period).Abs() <= offBurstMatch
	s.offBurstAt, s.offBurst = at, off
	r.logf("hbwatch: offburst svc=%s off=%d confirm=%t", svc, off.Milliseconds(), confirm)
	if !confirm || s.reconnect == nil || !gateOpen || !w.mayAct(s, now) {
		return
	}
	s.lastAction = now
	s.clearOffBurst()
	r.logf("hbwatch: offphase svc=%s off=%d action=%s", svc, off.Milliseconds(), ActionReconnect)
	r.actions = append(r.actions, s.reconnect)
}

// staleCheck runs the action of svc when its gap at at is over limit. Caller
// holds w.mu.
func (w *Watcher) staleCheck(svc Service, at time.Time, limit time.Duration, now time.Time, gateOpen bool, r *checkResult) {
	s := w.svcs[svc]
	if s.action == nil {
		return
	}
	gap := max(at.Sub(s.last), 0)
	if gap <= limit || !gateOpen || !w.mayAct(s, now) {
		return
	}
	s.lastAction = now
	r.logf("hbwatch: stale svc=%s gap=%d action=%s", svc, gap.Milliseconds(), s.kind)
	r.actions = append(r.actions, s.action)
}

// registered counts the services with a registered action. Caller holds w.mu.
func (w *Watcher) registered() int {
	n := 0
	for _, s := range w.svcs {
		if s.action != nil {
			n++
		}
	}
	return n
}

// CheckNow triggers a check after the grace, for a device wake or a path
// update. Wakes that land while one is pending collapse into it.
func (w *Watcher) CheckNow() {
	w.mu.Lock()
	if w.wakePending {
		w.mu.Unlock()
		return
	}
	w.wakePending = true
	w.wakeAt = w.now()
	w.mu.Unlock()
	w.clk.AfterFunc(Grace, w.checkWake)
}

// checkWake applies the period plus tolerance rule, measured at the wake. A
// burst that is open covers the wake.
func (w *Watcher) checkWake() {
	w.mu.Lock()
	w.wakePending = false
	at := w.wakeAt
	now := w.now()
	var r checkResult
	extra := ""
	if late := now.Sub(at.Add(Grace)); late > lateAfter {
		extra += fmt.Sprintf(" late=%d", late.Milliseconds())
	}
	if w.open != nil {
		r.logf("hbwatch: check trigger=%s members= gaps=%s wait=%d%s skipped=burst",
			triggerWake, w.gaps(at), now.Sub(at).Milliseconds(), extra)
		w.mu.Unlock()
		r.run()
		return
	}
	gateOpen := w.testHBActive(now)
	if !gateOpen {
		extra += " gate=closed"
	}
	r.logf("hbwatch: check trigger=%s members= gaps=%s wait=%d%s",
		triggerWake, w.gaps(at), now.Sub(at).Milliseconds(), extra)
	for _, name := range services {
		w.staleCheck(name, at, w.period+Tolerance, now, gateOpen, &r)
	}
	w.mu.Unlock()
	r.run()
}

// Register marks svc connected with its stale action and its reconnect for
// a wrong server skew, and resets its timestamp and off-burst state, so a
// fresh stream is not stale. The returned func unregisters it, and is a no-op
// once a newer Register for svc happened.
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
	s.clearOffBurst()
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
	w := New(realClock{}, period)
	log.Infof("hbwatch: enabled period=%s burst=%d tolerance=%s", period, w.burstDelay.Milliseconds(), Tolerance)
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

// burstDelayFromEnv returns NB_TEST_HB_BURST_DELAY_MS, default BurstDelay.
func burstDelayFromEnv() time.Duration {
	v, err := strconv.Atoi(os.Getenv(envBurstDelay))
	if err != nil || v <= 0 {
		return BurstDelay
	}
	return time.Duration(v) * time.Millisecond
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
