// Package hbwatch watches the aligned heartbeats of the Management, Signal and
// relay streams on a mobile client.
//
// Phase correction: the Management heartbeat is the reference. When a Signal or
// relay heartbeat lands more than CorrectThreshold away from it on two ticks in
// a row, at the same offset, the client asks that server for the phase that
// moves its heartbeat onto the Management one. The request goes out when the
// heartbeat arrives, inside the radio tail of that wake. Arrival times are
// compared on the client clock only, so the servers need no common clock.
//
// Stale check: the heartbeats of one tick form a burst. At each burst and each
// device wake, a registered stream that had heartbeats but has been silent for
// longer than the receive timeout of its own period (alignedhb.ReceiveTimeout)
// runs its stale action. A stream that is only off phase still lands within
// that time, so the phase correction gets to fix it first. Gaps are measured
// on the wall clock so time asleep counts. The check is on wherever the
// Watcher exists.
//
// Tick: the first heartbeat of each period, from any stream, runs the
// functions given to OnTick. Periodic client work hooked there runs inside a
// wake the device has anyway.
package hbwatch

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/alignedhb"
)

// Service names a watched stream.
type Service string

const (
	Management Service = "management"
	Signal     Service = "signal"
	Relay      Service = "relay"
)

const (
	// ActionReconnect names the stale action in its log line.
	ActionReconnect = "reconnect"

	defaultPeriod = alignedhb.DefaultPeriod
	// BurstDelay is how long after the first heartbeat of a burst the others
	// may join it. Cellular paging plus one TCP resend can delay a healthy
	// heartbeat 3 to 5 s.
	BurstDelay = 5 * time.Second
	// Grace lets the frames of a wake land before its check.
	Grace = 2 * time.Second
	// Tolerance covers arrival jitter on the action limit.
	Tolerance = 3 * time.Second
	// lateAfter marks a check whose timer ran this long after its time: the
	// phone slept past it.
	lateAfter = time.Second

	// CorrectThreshold is how far a heartbeat may land from the Management
	// heartbeat before its phase is corrected.
	CorrectThreshold = time.Second
	// refTolerance is how far a Management heartbeat may land from its previous
	// arrival plus the period and still serve as the reference.
	refTolerance = time.Second
	// offsetMatch is how close the offsets of two ticks must be to show one
	// constant wrong phase rather than jitter.
	offsetMatch = 500 * time.Millisecond
)

const (
	triggerBurst = "burst"
	triggerLone  = "lone"
	triggerWake  = "wake"
)

var services = []Service{Management, Signal, Relay}

// Heartbeat describes one aligned heartbeat: the period of its stream and the
// phase the server sent it on.
type Heartbeat struct {
	Period time.Duration
	Phase  time.Duration
	// Stream identifies the stream it came on, matched against
	// Registration.Stream. A client can hold several relay connections, and
	// only the registered one is corrected.
	Stream any
}

// Registration is what a connected stream hands to the Watcher.
type Registration struct {
	// Kind names the stale action in its log line.
	Kind string
	// Stale runs when the stream is found stale. Nil disables the stale check.
	Stale func()
	// Correct asks the server to send its heartbeats on phase. Nil disables the
	// phase correction. It must not block.
	Correct func(phase time.Duration)
	// Stream identifies the registered stream. Only heartbeats with the same
	// Stream are judged for a phase correction.
	Stream any
	// Addr is the server address, shown in the status.
	Addr string
	// AlignedPeriod is the heartbeat period the server confirmed when the
	// stream opened, zero when it opened stock or without a phase. A heartbeat
	// wake is then due before the first heartbeat arrives.
	AlignedPeriod time.Duration
	// Frames, when set, returns a count of the other inbound frames of the
	// stream, which show it alive. The Watcher reads it at heartbeats and
	// checks, so the per-frame path of the stream takes no lock and reads no
	// clock. A moved count dates the newest frame to the previous read.
	Frames func() uint64
}

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
	// period is the period of the last heartbeat of the current stream, zero
	// before the first one.
	period time.Duration
	reg    Registration
	regID  uint64
	// aligned is set once the current registration got a heartbeat. Only such
	// streams are checked: a stock stream sends none, so its gaps say nothing.
	aligned bool
	// openAt is when the current registration started.
	openAt time.Time
	// offAt is the arrival of the last off-phase heartbeat, zero when none; off
	// is its offset from the Management reference.
	offAt time.Time
	off   time.Duration

	// registered is set while a registration is active.
	registered bool
	// frames is the Registration.Frames count at framesAt, the previous read.
	frames   uint64
	framesAt time.Time
	// phase is the phase of the last heartbeat.
	phase time.Duration
	// pending is the correction asked on the last tick, resolved by the next
	// heartbeat. lastCorr is the last correction of the registration.
	pending  *Correction
	lastCorr *Correction
	// blocked counts corrections in a row the server did not apply. stopped is
	// set once it reached BlockAfter, with the server phase at that moment.
	blocked      int
	stopped      bool
	stoppedPhase time.Duration
}

// resetStream clears the per stream state for a new or ended registration.
func (s *service) resetStream() {
	s.aligned = false
	s.period = 0
	s.phase = 0
	s.pending = nil
	s.lastCorr = nil
	s.unblock()
	s.clearOffset()
}

func (s *service) clearOffset() {
	s.offAt = time.Time{}
	s.off = 0
}

// burst is one group of heartbeats waiting for its stale check.
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

// overdueSlack puts the overdue recheck after the receive timeout, where a
// stream that opened aligned stops counting as ticking.
const overdueSlack = time.Millisecond

// Watcher tracks the heartbeats of each service. Use New for tests; the
// package functions use a default Watcher.
type Watcher struct {
	clk        Clock
	period     time.Duration
	burstDelay time.Duration
	// staleOn reports whether stale checks run. Phase correction always runs.
	staleOn func() bool

	mu     sync.Mutex
	svcs   map[Service]*service
	nextID uint64
	// mgmtLast is the last Management heartbeat. mgmtRef is the last one that
	// came at its previous arrival plus the period, zero when the latest did not.
	mgmtLast time.Time
	mgmtRef  time.Time
	// mgmtPeriod is the period of the Management stream.
	mgmtPeriod time.Duration
	// open is the burst waiting for its check, nil when none.
	open        *burst
	burstGen    uint64
	wakePending bool
	wakeAt      time.Time
	// lastTick is the arrival of the heartbeat that started the current tick.
	lastTick  time.Time
	tickSubs  map[uint64]func(period time.Duration)
	nextTickN uint64

	// gate holds Management retries on a locked, idle device. It has its own
	// lock and is never called with w.mu held.
	gate *retryGate
	// wakes ends reconnect waits whose wall deadline passed while the device
	// slept. It has its own lock and is never called with w.mu held.
	wakes *wakeBus

	// history holds the latest corrections, oldest first. clampHits counts the
	// corrections per service the server did not apply in full.
	history   []*Correction
	clampHits map[Service]int
	// others holds relay connections a newer one replaced as the registered
	// stream, by Stream, while they are open.
	others map[any]*otherStream
}

// New returns a Watcher with stale checks on, the given clock and the stale
// check period.
func New(clk Clock, period time.Duration) *Watcher {
	w := &Watcher{
		clk:        clk,
		period:     period,
		burstDelay: BurstDelay,
		staleOn:    func() bool { return true },
		svcs:       map[Service]*service{},
		tickSubs:   map[uint64]func(time.Duration){},
		gate:       newRetryGate(),
		wakes:      newWakeBus(),
		clampHits:  map[Service]int{},
		others:     map[any]*otherStream{},
	}
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
// lock is released. Routine lines that come with every tick go to debugs,
// state changes to lines.
type checkResult struct {
	debugs  []string
	lines   []string
	warns   []string
	actions []func()
}

func (r *checkResult) debugf(format string, args ...any) {
	r.debugs = append(r.debugs, fmt.Sprintf(format, args...))
}

func (r *checkResult) logf(format string, args ...any) {
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}

func (r *checkResult) warnf(format string, args ...any) {
	r.warns = append(r.warns, fmt.Sprintf(format, args...))
}

func (r *checkResult) run() {
	for _, l := range r.debugs {
		log.Debug(l)
	}
	for _, l := range r.lines {
		log.Info(l)
	}
	for _, l := range r.warns {
		log.Warn(l)
	}
	for _, a := range r.actions {
		a()
	}
}

// Seen records an aligned heartbeat for svc. A Signal or relay heartbeat may
// trigger a phase correction. With stale checks on, it opens a burst when none
// is open and joins the open one otherwise.
func (w *Watcher) Seen(svc Service, hb Heartbeat) {
	w.mu.Lock()
	s, ok := w.svcs[svc]
	if !ok {
		w.mu.Unlock()
		return
	}
	now := w.now()
	w.sampleFrames(now)
	var r checkResult
	if !s.owns(hb.Stream) {
		// Another connection of the same service, such as a relay connection to
		// a peer's home relay. It is a wake like any other heartbeat, but says
		// nothing about the registered stream.
		w.seenOther(hb, now)
		w.startTick(hb.Period, now, &r)
		w.mu.Unlock()
		r.run()
		return
	}
	// Set before the settle below, so a heartbeat that comes after the burst
	// delay is not judged stale by its own arrival.
	s.last = now
	s.aligned = true
	s.phase = hb.Phase
	if hb.Period > 0 {
		s.period = hb.Period
	}

	if svc == Management {
		w.setReference(hb, now)
	} else {
		w.judgePhase(svc, hb, now, &r)
	}
	w.startTick(hb.Period, now, &r)

	if !w.staleOn() {
		w.mu.Unlock()
		r.run()
		return
	}
	gen, started := w.joinBurst(svc, now, &r)
	w.mu.Unlock()

	r.run()
	log.Debugf("hbwatch: seen svc=%s t=%d", svc, now.UnixMilli())
	if started {
		log.Debugf("hbwatch: burst start svc=%s t=%d", svc, now.UnixMilli())
		w.clk.AfterFunc(w.burstDelay, func() { w.checkBurst(gen) })
	}
}

// startTick queues the tick functions when the heartbeat at now is the first
// of its period. The streams of one tick land within a few seconds, well under
// half a period. A clock that went back starts a new tick. Caller holds w.mu.
func (w *Watcher) startTick(period time.Duration, now time.Time, r *checkResult) {
	if period <= 0 {
		period = w.period
	}
	if gap := now.Sub(w.lastTick); !w.lastTick.IsZero() && gap >= 0 && gap < period/2 {
		return
	}
	w.lastTick = now
	gate, wakes := w.gate, w.wakes
	r.actions = append(r.actions, func() {
		gate.wake(now)
		wakes.fire(Wake{Kind: WakeBurst, At: now})
	})
	for _, f := range w.tickSubs {
		r.actions = append(r.actions, func() { f(period) })
	}
}

// OnTick registers f to run on every tick with the heartbeat period. f runs on
// the goroutine that received the heartbeat and must not block. The returned
// func unregisters it.
func (w *Watcher) OnTick(f func(period time.Duration)) (unsubscribe func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.nextTickN++
	n := w.nextTickN
	w.tickSubs[n] = f
	return func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		delete(w.tickSubs, n)
	}
}

// joinBurst adds svc to the open burst or opens one. A burst whose check is
// due but has not run, because the phone slept past its timer, is judged
// first. Caller holds w.mu.
func (w *Watcher) joinBurst(svc Service, now time.Time, r *checkResult) (gen uint64, started bool) {
	if b := w.open; b != nil && now.After(b.start.Add(w.burstDelay)) {
		w.open = nil
		w.evalBurst(b, now, r)
	}
	started = w.open == nil
	if started {
		w.burstGen++
		w.open = &burst{gen: w.burstGen, start: now}
	}
	b := w.open
	if !b.has(svc) {
		b.members = append(b.members, svc)
	}
	return b.gen, started
}

// setReference records a Management heartbeat. It is the reference for the
// phase correction only when it came at its previous arrival plus the period:
// a delayed or early one would move every stream with it. Caller holds w.mu.
func (w *Watcher) setReference(hb Heartbeat, now time.Time) {
	onTime := !w.mgmtLast.IsZero() && hb.Period > 0 &&
		(now.Sub(w.mgmtLast)-hb.Period).Abs() <= refTolerance
	w.mgmtLast = now
	w.mgmtPeriod = hb.Period
	if onTime {
		w.mgmtRef = now
		return
	}
	w.mgmtRef = time.Time{}
}

// judgePhase compares a Signal or relay heartbeat with the Management
// reference and asks for a new phase when the offset is the same on two ticks
// in a row. Without a recent reference on the same period nothing changes, so
// the streams keep their phase while Management is gone. Caller holds w.mu.
func (w *Watcher) judgePhase(svc Service, hb Heartbeat, now time.Time, r *checkResult) {
	s := w.svcs[svc]
	period := hb.Period
	if s.reg.Correct == nil || hb.Stream != s.reg.Stream || period <= 0 || !alignedhb.ValidPhase(hb.Phase, period) {
		return
	}
	w.resolvePending(svc, s, hb, now, r)
	if period != w.mgmtPeriod || w.mgmtRef.IsZero() || now.Sub(w.mgmtRef) > period+refTolerance {
		s.clearOffset()
		return
	}
	off := centered(now.Sub(w.mgmtRef), period)
	if off.Abs() <= CorrectThreshold {
		s.clearOffset()
		s.unblock()
		return
	}
	if s.correctionsStopped(hb.Phase) {
		s.clearOffset()
		return
	}
	since := now.Sub(s.offAt)
	confirm := !s.offAt.IsZero() && since >= period/2 && since <= period*3/2 &&
		centered(off-s.off, period).Abs() <= offsetMatch
	if !confirm {
		s.offAt, s.off = now, off
		r.debugf("hbwatch: offphase svc=%s off=%d confirm=false", svc, off.Milliseconds())
		return
	}
	s.clearOffset()
	phase := wantedPhase(hb.Phase, off, period)
	r.logf("hbwatch: correct svc=%s off=%d phase=%d wanted=%d",
		svc, off.Milliseconds(), hb.Phase.Milliseconds(), phase.Milliseconds())
	w.recordCorrection(s, &Correction{
		At: now, Service: svc, Addr: s.reg.Addr, Offset: off, From: hb.Phase, Wanted: phase, Result: ResultPending,
	})
	correct := s.reg.Correct
	r.actions = append(r.actions, func() { correct(phase) })
}

// wantedPhase returns the phase that moves a heartbeat sent on phase and seen
// off away from the reference onto it, in whole milliseconds.
func wantedPhase(phase, off, period time.Duration) time.Duration {
	p := (phase - off).Round(time.Millisecond)
	return (p%period + period) % period
}

// Touch records any other inbound frame for svc. It counts as alive but never
// opens or joins a burst.
func (w *Watcher) Touch(svc Service) {
	w.TouchStream(svc, nil)
}

// TouchStream records any other inbound frame for svc that came on stream,
// matched against Registration.Stream. A frame from another connection of the
// service is ignored, a nil stream counts for the registered one.
func (w *Watcher) TouchStream(svc Service, stream any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if s, ok := w.svcs[svc]; ok && s.owns(stream) {
		s.last = w.now()
	}
}

// owns reports whether a frame from stream belongs to the registered stream. A
// registration without a Stream owns every frame of its service, and an
// untagged frame counts for the registered stream.
func (s *service) owns(stream any) bool {
	return s.reg.Stream == nil || stream == nil || stream == s.reg.Stream
}

// streamPeriod returns the period of the current stream of s, or the watcher
// period before its first heartbeat. Caller holds w.mu.
func (w *Watcher) streamPeriod(s *service) time.Duration {
	if s.period > 0 {
		return s.period
	}
	return w.period
}

// mayAct reports whether s had no action within the last period. Arrival
// jitters, so the next tick may come a little under one period after the last
// action. Caller holds w.mu.
func (w *Watcher) mayAct(s *service, now time.Time) bool {
	return s.lastAction.IsZero() || now.Sub(s.lastAction) >= w.streamPeriod(s)-Tolerance
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
	var r checkResult
	w.evalBurst(b, w.now(), &r)
	w.mu.Unlock()
	r.run()
}

// gaps formats the gap of every service at t, -1 for one not checked.
// Caller holds w.mu.
func (w *Watcher) gaps(t time.Time) string {
	out := make([]string, 0, len(services))
	for _, name := range services {
		s := w.svcs[name]
		if !s.checked() {
			out = append(out, string(name)+":-1")
			continue
		}
		out = append(out, fmt.Sprintf("%s:%d", name, max(t.Sub(s.last), 0).Milliseconds()))
	}
	return strings.Join(out, ",")
}

// checked reports whether the stale check covers s: it has a stale action and
// its current stream sent heartbeats.
func (s *service) checked() bool {
	return s.reg.Stale != nil && s.aligned
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

// evalBurst runs the check of burst b at now. Gaps are measured at the burst
// start, so a frame that landed during the burst counts as no gap. Caller
// holds w.mu.
func (w *Watcher) evalBurst(b *burst, now time.Time, r *checkResult) {
	at := b.start
	trigger := burstTrigger(b)

	extra := ""
	if late := now.Sub(at.Add(w.burstDelay)); late > lateAfter {
		extra += fmt.Sprintf(" late=%d", late.Milliseconds())
	}
	r.debugf("hbwatch: check trigger=%s members=%s gaps=%s wait=%d%s",
		trigger, joinMembers(b), w.gaps(at), now.Sub(at).Milliseconds(), extra)

	for _, name := range services {
		if !b.has(name) {
			w.staleCheck(name, at, now, r)
		}
	}
}

// staleCheck runs the action of svc when its gap at the check time is over
// the receive timeout of its period. Caller holds w.mu.
func (w *Watcher) staleCheck(svc Service, at time.Time, now time.Time, r *checkResult) {
	s := w.svcs[svc]
	if !s.checked() {
		return
	}
	s.sampleFrames(now)
	gap := max(at.Sub(s.last), 0)
	if gap <= alignedhb.ReceiveTimeout(w.streamPeriod(s)) || !w.mayAct(s, now) {
		return
	}
	s.lastAction = now
	r.logf("hbwatch: stale svc=%s gap=%d action=%s", svc, gap.Milliseconds(), s.reg.Kind)
	r.actions = append(r.actions, s.reg.Stale)
}

// CheckNow triggers a stale check after the grace, for a device wake or a
// path update. The wake also lets a held Management retry through and ends the
// reconnect waits whose wall deadline passed. A wake that lands while one is
// pending replaces it: the timer of the pending one can sleep with the phone,
// and its wake time is then old.
func (w *Watcher) CheckNow() {
	now := w.now()
	w.gate.wake(now)
	w.wakes.fire(Wake{Kind: WakeDevice, At: now})
	if !w.staleOn() {
		return
	}
	w.mu.Lock()
	w.wakeAt = w.now()
	if w.wakePending {
		w.mu.Unlock()
		return
	}
	w.wakePending = true
	w.mu.Unlock()
	w.clk.AfterFunc(Grace, w.checkWake)
}

// checkWake applies the receive timeout rule, measured at the wake. A
// burst that opened at the wake covers it. A burst whose check the phone slept
// past is judged first.
func (w *Watcher) checkWake() {
	w.mu.Lock()
	at := w.wakeAt
	now := w.now()
	if rest := min(Grace-now.Sub(at), Grace); rest > 0 {
		// A newer wake took over this timer; its frames get the grace too.
		w.mu.Unlock()
		w.clk.AfterFunc(rest, w.checkWake)
		return
	}
	w.wakePending = false
	var r checkResult
	if b := w.open; b != nil && at.After(b.start.Add(w.burstDelay)) {
		w.open = nil
		w.evalBurst(b, now, &r)
	}
	extra := ""
	if late := now.Sub(at.Add(Grace)); late > lateAfter {
		extra += fmt.Sprintf(" late=%d", late.Milliseconds())
	}
	if w.open != nil {
		r.debugf("hbwatch: check trigger=%s members= gaps=%s wait=%d%s skipped=burst",
			triggerWake, w.gaps(at), now.Sub(at).Milliseconds(), extra)
		w.mu.Unlock()
		r.run()
		return
	}
	r.debugf("hbwatch: check trigger=%s members= gaps=%s wait=%d%s",
		triggerWake, w.gaps(at), now.Sub(at).Milliseconds(), extra)
	for _, name := range services {
		w.staleCheck(name, at, now, &r)
	}
	w.mu.Unlock()
	r.run()
}

// Register marks svc connected with reg, and resets its timestamp and phase
// state, so a fresh stream is neither stale nor corrected for its predecessor.
// The returned func unregisters it, and is a no-op once a newer Register for
// svc happened.
func (w *Watcher) Register(svc Service, reg Registration) (unregister func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	s, ok := w.svcs[svc]
	if !ok {
		return func() {}
	}
	w.nextID++
	id := w.nextID
	w.keepReplaced(svc, s)
	s.regID = id
	s.reg = reg
	s.registered = true
	s.resetStream()
	s.last = w.now()
	s.openAt = s.last
	s.startFrames(s.last)
	if svc == Management {
		w.mgmtLast, w.mgmtRef = time.Time{}, time.Time{}
	}
	if reg.AlignedPeriod > 0 {
		// A held Management retry must not wait for a heartbeat that never
		// comes: recheck once the first one is overdue. ticks still counts the
		// stream at exactly the receive timeout, so recheck just past it.
		w.clk.AfterFunc(alignedhb.ReceiveTimeout(reg.AlignedPeriod)+overdueSlack, w.gate.recheck)
	}
	return func() {
		w.mu.Lock()
		if s.regID != id {
			if reg.Stream != nil {
				delete(w.others, reg.Stream)
			}
			w.mu.Unlock()
			return
		}
		s.reg = Registration{}
		s.registered = false
		s.resetStream()
		if svc == Management {
			w.mgmtLast, w.mgmtRef = time.Time{}, time.Time{}
		}
		w.restoreReplaced(svc, s)
		w.mu.Unlock()
		w.gate.recheck()
	}
}

// keepReplaced moves the registered stream of s to the other streams when a
// new registration replaces it while it stays open, as a relay connection to
// another server does. Caller holds w.mu.
func (w *Watcher) keepReplaced(svc Service, s *service) {
	if !s.registered || s.reg.Stream == nil {
		return
	}
	w.others[s.reg.Stream] = &otherStream{
		addr: s.reg.Addr, aligned: s.aligned, period: s.period, phase: s.phase, last: s.last,
		svc: svc, reg: s.reg, id: s.regID, openAt: s.openAt,
	}
}

// restoreReplaced gives the slot of svc, which its stream just left, back to
// the newest replaced stream of svc that is still open. A relay candidate that lost the
// server pick can register after the winner and close right after it, and
// the winner must not be left unwatched. Caller holds w.mu.
func (w *Watcher) restoreReplaced(svc Service, s *service) {
	var key any
	var newest *otherStream
	for k, o := range w.others {
		if o.svc == svc && (newest == nil || o.id > newest.id) {
			key, newest = k, o
		}
	}
	if newest == nil {
		return
	}
	delete(w.others, key)
	s.regID = newest.id
	s.reg = newest.reg
	s.registered = true
	s.aligned, s.period, s.phase = newest.aligned, newest.period, newest.phase
	s.last, s.openAt = newest.last, newest.openAt
	s.startFrames(w.now())
}

// startFrames takes the first frame count of a new registration at now.
func (s *service) startFrames(now time.Time) {
	s.frames, s.framesAt = 0, now
	if s.reg.Frames != nil {
		s.frames = s.reg.Frames()
	}
}

// sampleFrames reads the frame count of s at now. When it moved, a frame came
// after the previous read, so the stream was alive at that read at least.
// Caller holds w.mu.
func (s *service) sampleFrames(now time.Time) {
	if s.reg.Frames == nil {
		return
	}
	if n := s.reg.Frames(); n != s.frames {
		s.frames = n
		if s.framesAt.After(s.last) {
			s.last = s.framesAt
		}
	}
	s.framesAt = now
}

// sampleFrames reads the frame counts of all services at now, at every
// heartbeat. Caller holds w.mu.
func (w *Watcher) sampleFrames(now time.Time) {
	for _, s := range w.svcs {
		s.sampleFrames(now)
	}
}

// seenOther records a heartbeat of a replaced stream. Caller holds w.mu.
func (w *Watcher) seenOther(hb Heartbeat, now time.Time) {
	o, ok := w.others[hb.Stream]
	if hb.Stream == nil || !ok {
		return
	}
	o.aligned = true
	o.last = now
	o.phase = hb.Phase
	if hb.Period > 0 {
		o.period = hb.Period
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

// ticks reports whether a heartbeat wake is due from the stream of s at now:
// it got a heartbeat, or it opened aligned and its first heartbeat may still
// come within the receive timeout. Caller holds w.mu.
func (s *service) ticks(now time.Time) bool {
	if s.reg.Stale == nil && s.reg.Correct == nil {
		return false
	}
	if s.aligned {
		return true
	}
	p := s.reg.AlignedPeriod
	return p > 0 && now.Sub(s.openAt) <= alignedhb.ReceiveTimeout(p)
}

var (
	defaultMu      sync.Mutex
	defaultSet     atomic.Bool
	defaultWatcher atomic.Pointer[Watcher]
)

// def returns the default Watcher. It exists only on builds that ask for the
// aligned heartbeat, so a missing result is kept.
func def() *Watcher {
	if w := defaultWatcher.Load(); w != nil || defaultSet.Load() {
		return w
	}
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if w := defaultWatcher.Load(); w != nil || defaultSet.Load() {
		return w
	}
	if !staleEnabled() {
		defaultSet.Store(true)
		return nil
	}
	w := New(realClock{}, defaultPeriod)
	w.staleOn = staleEnabled
	log.Infof("hbwatch: on, stale check %t, period %s, burst %d ms", staleEnabled(), defaultPeriod, w.burstDelay.Milliseconds())
	defaultWatcher.Store(w)
	return w
}

// staleEnabled reports whether stale checks run: on builds that ask for the
// aligned heartbeat.
func staleEnabled() bool {
	return alignedhb.Supported()
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

// Seen records a heartbeat on the default Watcher. No-op without one.
func Seen(svc Service, hb Heartbeat) {
	if w := def(); w != nil {
		w.Seen(svc, hb)
	}
}

// Touch records another inbound frame on the default Watcher. No-op without one.
func Touch(svc Service) {
	if w := def(); w != nil {
		w.Touch(svc)
	}
}

// TouchStream records another inbound frame from stream on the default
// Watcher. No-op without one.
func TouchStream(svc Service, stream any) {
	if w := def(); w != nil {
		w.TouchStream(svc, stream)
	}
}

// CheckNow triggers a stale check on the default Watcher. Safe before any
// service registered and after all stopped. No-op without stale checks.
func CheckNow() {
	if w := def(); w != nil {
		w.CheckNow()
	}
}

// OnTick registers f on the default Watcher. ok is false when this build has
// no Watcher: then no tick ever comes and unsubscribe is a no-op.
func OnTick(f func(period time.Duration)) (unsubscribe func(), ok bool) {
	if w := def(); w != nil {
		return w.OnTick(f), true
	}
	return func() {}, false
}

// Register registers svc on the default Watcher. No-op without one.
func Register(svc Service, reg Registration) (unregister func()) {
	if w := def(); w != nil {
		return w.Register(svc, reg)
	}
	return func() {}
}

// Reset resets svc on the default Watcher. No-op without one.
func Reset(svc Service) {
	if w := def(); w != nil {
		w.Reset(svc)
	}
}
