// Package hbwatch watches the aligned heartbeats of the Management, Signal
// and relay streams on a mobile client.
//
// Stale check: one global tick number, raised by the first heartbeat at
// least half a period after the previous tick; heartbeats that land sooner
// join that tick. Each stream stores the tick of its last heartbeat, and at
// a new tick a stream two or more ticks behind runs its stale action. A
// heartbeat held by the network therefore opens or joins one tick and never
// makes a live stream look dead. A device wake runs the wake check: after a
// short grace, a stream silent for longer than its receive timeout on the
// wall clock runs its stale action, which covers the time the phone slept
// and no tick could form.
//
// Tick: the first heartbeat of each tick also runs the functions given to
// OnTick, so periodic client work runs inside a wake the device has anyway.
package hbwatch

import (
	"context"
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

	// Grace lets the frames of a wake land before its check runs.
	Grace = 2 * time.Second
)

var (
	services = []Service{Management, Signal, Relay}

	defaultMu      sync.Mutex
	defaultSet     atomic.Bool
	defaultWatcher atomic.Pointer[Watcher]
)

// Registration is what a connected stream hands to the Watcher.
type Registration struct {
	// Kind names the stale action in its log line.
	Kind string
	// Stale runs when the stream is found stale. Nil disables the stale check.
	Stale func()
	// Addr is the server address, shown in the status.
	Addr string
	// AlignedPeriod is the heartbeat period the server confirmed when the
	// stream opened, zero when it opened stock.
	AlignedPeriod time.Duration
}

// StreamStatus is the aligned heartbeat state of one registered stream.
type StreamStatus struct {
	Service Service
	Addr    string
	// Aligned reports whether the stream got an aligned heartbeat.
	Aligned bool
	// Period is the heartbeat period of the stream, zero before it is known.
	Period time.Duration
}

// Snapshot is the aligned heartbeat state of every registered stream.
type Snapshot struct {
	Streams []StreamStatus
}

// wakeEvent is one device wake at wall time at.
type wakeEvent struct {
	at time.Time
}

// Clock is the time source. Now must return wall time; AfterFunc schedules f.
type Clock interface {
	Now() time.Time
	AfterFunc(d time.Duration, f func())
}

type realClock struct{}

type service struct {
	reg        Registration
	regID      uint64
	registered bool
	// aligned is set once the current registration got a heartbeat. Only
	// such streams take part in the tick stale check: a stock stream sends
	// none, so its gaps say nothing.
	aligned bool
	// period is the period of the stream: the confirmed period at
	// registration, then the period of its heartbeats.
	period time.Duration
	// last is the wall time of the last heartbeat, or of the registration.
	last time.Time
	// tick is the global tick number of the last heartbeat.
	tick uint64
	// lastAction is when the stale action last ran for this stream.
	lastAction time.Time
}

// Watcher tracks the heartbeats of each service. Use New for tests; the
// package functions use a default Watcher.
type Watcher struct {
	clk    Clock
	period time.Duration

	mu        sync.Mutex
	svcs      map[Service]*service
	nextID    uint64
	tick      uint64
	lastTick  time.Time
	tickSubs  map[uint64]func(period time.Duration)
	nextTickN uint64
	wakeAt    time.Time
	wakePend  bool
	wakeSubs  map[uint64]chan wakeEvent
	nextWakeN uint64
}

// New returns a Watcher on the given clock. period is the heartbeat period
// used before a stream reports its own.
func New(clk Clock, period time.Duration) *Watcher {
	w := &Watcher{
		clk:      clk,
		period:   period,
		svcs:     map[Service]*service{},
		tickSubs: map[uint64]func(period time.Duration){},
		wakeSubs: map[uint64]chan wakeEvent{},
	}
	for _, s := range services {
		w.svcs[s] = &service{}
	}
	return w
}

// Register marks svc connected with reg and resets its heartbeat state, so
// a fresh stream is not judged for its predecessor. The returned func
// unregisters it, and is a no-op once a newer Register for svc happened.
func (w *Watcher) Register(svc Service, reg Registration) (unregister func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	s, ok := w.svcs[svc]
	if !ok {
		return func() {}
	}
	w.nextID++
	id := w.nextID
	s.reg = reg
	s.regID = id
	s.registered = true
	s.aligned = false
	s.period = reg.AlignedPeriod
	s.last = w.now()
	s.tick = w.tick
	s.lastAction = time.Time{}
	return func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if s.regID != id {
			return
		}
		s.reg = Registration{}
		s.registered = false
		s.aligned = false
		s.period = 0
	}
}

// Confirm records the heartbeat period the server confirmed for the current
// registration of svc. A stream that registers before its aligned answer
// calls it at the answer, so the wake check judges the stream before its
// first heartbeat. A period of zero or less, or an unregistered svc, is
// ignored.
func (w *Watcher) Confirm(svc Service, period time.Duration) {
	if period <= 0 {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	s, ok := w.svcs[svc]
	if !ok || !s.registered {
		return
	}
	s.reg.AlignedPeriod = period
	s.period = period
}

// Seen records an aligned heartbeat for svc with the given period. It
// raises the global tick when the heartbeat is the first at least half a
// period after the previous tick, joins the current tick otherwise, and
// runs the stale action of every stream two or more ticks behind.
func (w *Watcher) Seen(svc Service, period time.Duration) {
	w.mu.Lock()
	s, ok := w.svcs[svc]
	if !ok || !s.registered {
		w.mu.Unlock()
		return
	}
	now := w.now()
	if period > 0 {
		s.period = period
	}
	s.last = now
	s.aligned = true

	tickPeriod := s.period
	if tickPeriod <= 0 {
		tickPeriod = w.period
	}
	gap := now.Sub(w.lastTick)
	if !w.lastTick.IsZero() && gap >= 0 && gap < tickPeriod/2 {
		s.tick = w.tick
		w.mu.Unlock()
		return
	}

	w.tick++
	w.lastTick = now
	s.tick = w.tick
	subs := make([]func(time.Duration), 0, len(w.tickSubs))
	for _, f := range w.tickSubs {
		subs = append(subs, f)
	}
	var actions []func()
	for _, name := range services {
		st := w.svcs[name]
		if st == s || !st.registered || !st.aligned || st.reg.Stale == nil {
			continue
		}
		if w.tick-st.tick < 2 {
			continue
		}
		behind := w.tick - st.tick
		// Bump the stream to this tick: a still-dead stream is acted on
		// again after two more ticks, not on every tick.
		st.tick = w.tick
		st.lastAction = now
		log.Infof("hbwatch: stale svc=%s ticks=%d action=%s", name, behind, st.reg.Kind)
		actions = append(actions, st.reg.Stale)
	}
	w.mu.Unlock()

	for _, f := range subs {
		f(tickPeriod)
	}
	for _, a := range actions {
		a()
	}
}

// OnTick registers f to run on every tick with the heartbeat period. f runs
// on the goroutine that received the heartbeat and must not block. The
// returned func unregisters it.
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

// CheckNow runs the wake check after the grace: a stream silent for longer
// than its receive timeout at the wake, measured on the wall clock, runs
// its stale action. It also fires a wake for the retry waits. A wake that
// lands while one is pending replaces its time: the timer of the pending
// one can sleep with the phone, and its wake time is then old.
func (w *Watcher) CheckNow() {
	now := w.now()
	w.fireWake(wakeEvent{at: now})

	w.mu.Lock()
	w.wakeAt = now
	if w.wakePend {
		w.mu.Unlock()
		return
	}
	w.wakePend = true
	w.mu.Unlock()
	w.clk.AfterFunc(Grace, w.checkWake)
}

// WaitRetryDelay waits d after a failed attempt. The wait ends when its
// timer fires, on netChanged, or at a device wake once the wall deadline
// (now plus d) has passed, which covers the time the device slept and the
// timer did not count. A wall clock that went back never holds it past the
// timer. It returns ctx.Err() when ctx is done.
func (w *Watcher) WaitRetryDelay(ctx context.Context, d time.Duration, netChanged <-chan struct{}) error {
	deadline := w.now().Add(d)
	timer := time.NewTimer(d)
	defer timer.Stop()
	wakes, unsubscribe := w.subscribeWake()
	defer unsubscribe()
	for {
		select {
		case <-timer.C:
			return nil
		case <-netChanged:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case wake := <-wakes:
			if !wake.at.Before(deadline) {
				log.Debugf("hbwatch: retry wait ended by wake overdue=%d", wake.at.Sub(deadline).Milliseconds())
				return nil
			}
		}
	}
}

// Snapshot returns the aligned heartbeat state of the registered streams.
func (w *Watcher) Snapshot() Snapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	snap := Snapshot{}
	for _, name := range services {
		s := w.svcs[name]
		if !s.registered {
			continue
		}
		snap.Streams = append(snap.Streams, StreamStatus{
			Service: name,
			Addr:    s.reg.Addr,
			Aligned: s.aligned,
			Period:  s.period,
		})
	}
	return snap
}

// SetDefault replaces the default Watcher, for tests in packages that call
// the package functions. The returned func restores the previous one.
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

// Register registers svc on the default Watcher. No-op without one.
func Register(svc Service, reg Registration) (unregister func()) {
	if w := def(); w != nil {
		return w.Register(svc, reg)
	}
	return func() {}
}

// Confirm records a confirmed period on the default Watcher. No-op without
// one.
func Confirm(svc Service, period time.Duration) {
	if w := def(); w != nil {
		w.Confirm(svc, period)
	}
}

// Seen records a heartbeat on the default Watcher. No-op without one.
func Seen(svc Service, period time.Duration) {
	if w := def(); w != nil {
		w.Seen(svc, period)
	}
}

// CheckNow triggers the wake check on the default Watcher. Safe before any
// service registered and after all stopped. No-op without one.
func CheckNow() {
	if w := def(); w != nil {
		w.CheckNow()
	}
}

// OnTick registers f on the default Watcher. ok is false when this build
// has no Watcher: then no tick ever comes and unsubscribe is a no-op.
func OnTick(f func(period time.Duration)) (unsubscribe func(), ok bool) {
	if w := def(); w != nil {
		return w.OnTick(f), true
	}
	return func() {}, false
}

// WaitRetryDelay waits on the default Watcher. Without one it is a plain
// timer that netChanged cuts short.
func WaitRetryDelay(ctx context.Context, d time.Duration, netChanged <-chan struct{}) error {
	if w := def(); w != nil {
		return w.WaitRetryDelay(ctx, d, netChanged)
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-netChanged:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// CurrentSnapshot returns the state of the default Watcher. ok is false
// when this build has no Watcher.
func CurrentSnapshot() (Snapshot, bool) {
	if w := def(); w != nil {
		return w.Snapshot(), true
	}
	return Snapshot{}, false
}

// def returns the default Watcher. It exists only on builds that ask for
// the aligned heartbeat, so a missing result is kept.
func def() *Watcher {
	if w := defaultWatcher.Load(); w != nil || defaultSet.Load() {
		return w
	}
	defaultMu.Lock()
	defer defaultMu.Unlock()
	if w := defaultWatcher.Load(); w != nil || defaultSet.Load() {
		return w
	}
	defaultSet.Store(true)
	if !alignedhb.Supported() {
		return nil
	}
	w := New(realClock{}, alignedhb.DefaultPeriod)
	defaultWatcher.Store(w)
	return w
}

func (w *Watcher) now() time.Time {
	// Round(0) strips the monotonic reading, so differences are wall time.
	return w.clk.Now().Round(0)
}

func (w *Watcher) checkWake() {
	w.mu.Lock()
	at := w.wakeAt
	if rest := Grace - w.now().Sub(at); rest > 0 {
		// A newer wake took over this timer; its frames get the grace too.
		w.mu.Unlock()
		w.clk.AfterFunc(rest, w.checkWake)
		return
	}
	w.wakePend = false
	now := w.now()
	var actions []func()
	for _, name := range services {
		s := w.svcs[name]
		if !s.registered || s.reg.Stale == nil {
			continue
		}
		period := s.period
		if period <= 0 {
			period = w.period
		}
		if !s.aligned && s.reg.AlignedPeriod <= 0 {
			continue
		}
		if at.Sub(s.last) <= alignedhb.ReceiveTimeout(period) {
			continue
		}
		if !s.lastAction.IsZero() && now.Sub(s.lastAction) < period {
			continue
		}
		s.lastAction = now
		log.Infof("hbwatch: stale svc=%s gap=%d action=%s trigger=wake", name, at.Sub(s.last).Milliseconds(), s.reg.Kind)
		actions = append(actions, s.reg.Stale)
	}
	w.mu.Unlock()
	for _, a := range actions {
		a()
	}
}

// fireWake hands wake to every retry waiter. A waiter that has not read its
// last wake gets the newer of the two instead: an old wake can be before the
// deadline of the wait while the new one is past it. The sends run under mu,
// so only one sender fills a slot it just emptied.
func (w *Watcher) fireWake(wake wakeEvent) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, ch := range w.wakeSubs {
		select {
		case ch <- wake:
			continue
		default:
		}
		latest := wake
		select {
		case old := <-ch:
			if old.at.After(latest.at) {
				latest = old
			}
		default:
		}
		select {
		case ch <- latest:
		default:
		}
	}
}

func (w *Watcher) subscribeWake() (<-chan wakeEvent, func()) {
	ch := make(chan wakeEvent, 1)
	w.mu.Lock()
	w.nextWakeN++
	n := w.nextWakeN
	w.wakeSubs[n] = ch
	w.mu.Unlock()
	return ch, func() {
		w.mu.Lock()
		delete(w.wakeSubs, n)
		w.mu.Unlock()
	}
}

func (realClock) Now() time.Time                      { return time.Now() }
func (realClock) AfterFunc(d time.Duration, f func()) { time.AfterFunc(d, f) }
