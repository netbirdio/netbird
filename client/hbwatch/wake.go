package hbwatch

import (
	"context"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// WakeKind names what gave the device a wake.
type WakeKind string

const (
	// WakeBurst is the first heartbeat of a tick.
	WakeBurst WakeKind = "burst"
	// WakeDevice is a wake the app reported.
	WakeDevice WakeKind = "device"
)

// WaitKey names a reconnect wait in the log.
type WaitKey string

// The reconnect waits of Management, Signal and relay.
const (
	WaitSync          WaitKey = WaitKey(RetrySync)
	WaitJob           WaitKey = WaitKey(RetryJob)
	WaitMgmtConnect   WaitKey = "mgmt-connect"
	WaitMgmtLogin     WaitKey = "mgmt-login"
	WaitMgmtDial      WaitKey = WaitKey(RetryDial)
	WaitSignalReceive WaitKey = "signal"
	WaitSignalConnect WaitKey = "signal-connect"
	WaitRelay         WaitKey = "relay"
)

// Wake is one burst tick or device wake at wall time At. Slept is the wall
// time the device last went to sleep before a device wake, zero when no sleep
// was reported or for a burst.
type Wake struct {
	Kind  WakeKind
	At    time.Time
	Slept time.Time
}

// wakeEvent is the next wake. done is closed once wake is set.
type wakeEvent struct {
	done chan struct{}
	wake Wake
}

// wakeBus hands every wake to the waits and subscribers. Go timers count only
// awake time on mobile, so a wait checks its wall deadline at each wake too.
type wakeBus struct {
	mu    sync.Mutex
	next  *wakeEvent
	subs  map[uint64]func(Wake)
	subID uint64
	// sleptAt is the last time the app reported the device asleep.
	sleptAt time.Time
	// early is the wake of the last early end of a retry wait, per key.
	early map[WaitKey]time.Time
}

func newWakeBus() *wakeBus {
	return &wakeBus{
		next:  &wakeEvent{done: make(chan struct{})},
		subs:  map[uint64]func(Wake){},
		early: map[WaitKey]time.Time{},
	}
}

// takeEarly records an early end of the wait for key at a wake at at, unless
// the previous one was less than period ago. A clock that went back never
// blocks it.
func (b *wakeBus) takeEarly(key WaitKey, at time.Time, period time.Duration) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if last, ok := b.early[key]; ok {
		if gap := at.Sub(last); gap >= 0 && gap < period-Tolerance {
			return false
		}
	}
	b.early[key] = at
	return true
}

// pending returns the event of the next wake.
func (b *wakeBus) pending() *wakeEvent {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.next
}

// sleep records that the device went to sleep at at.
func (b *wakeBus) sleep(at time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sleptAt = at
}

// fire wakes the waits and runs the subscribers on the calling goroutine.
func (b *wakeBus) fire(w Wake) {
	b.mu.Lock()
	if w.Kind == WakeDevice {
		w.Slept = b.sleptAt
	}
	ev := b.next
	b.next = &wakeEvent{done: make(chan struct{})}
	subs := make([]func(Wake), 0, len(b.subs))
	for _, f := range b.subs {
		subs = append(subs, f)
	}
	b.mu.Unlock()

	ev.wake = w
	close(ev.done)
	for _, f := range subs {
		f(w)
	}
}

func (b *wakeBus) subscribe(f func(Wake)) (unsubscribe func()) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subID++
	id := b.subID
	b.subs[id] = f
	return func() {
		b.mu.Lock()
		defer b.mu.Unlock()
		delete(b.subs, id)
	}
}

// OnWake registers f to run on every burst tick and device wake. f runs on
// the goroutine that saw the wake and must not block. The returned func
// unregisters it.
func (w *Watcher) OnWake(f func(Wake)) (unsubscribe func()) {
	return w.wakes.subscribe(f)
}

// WaitRetryDelay waits d after a failed attempt for key. The wait ends when
// its timer fires, on netChanged, or at a wake when the wall deadline (now
// plus d) passed, which covers the time the device slept and the timer did
// not count. While no stream ticks, a device wake after a sleep during the
// wait ends it too, at most once per key per period: no burst will come, so
// that wake is the only chance to reconnect, but peer keepalives can wake
// the device far more often. A wall clock that went back never holds it past
// the timer. It returns ctx.Err() when ctx is done.
func (w *Watcher) WaitRetryDelay(ctx context.Context, key WaitKey, d time.Duration, netChanged <-chan struct{}) error {
	start := w.now()
	deadline := start.Add(d)
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		ev := w.wakes.pending()
		select {
		case <-timer.C:
			return nil
		case <-netChanged:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		case <-ev.done:
			if overdue := ev.wake.At.Sub(deadline); overdue >= 0 || w.onlyChance(key, ev.wake, start) {
				LogWaitWoken(key, overdue, ev.wake.Kind)
				return nil
			}
		}
	}
}

// onlyChance reports whether wake is a device wake after a sleep that began
// after start, while no stream ticks, and the wait for key did not end early
// in the last period.
func (w *Watcher) onlyChance(key WaitKey, wake Wake, start time.Time) bool {
	if wake.Kind != WakeDevice || !wake.Slept.After(start) || w.anyTicks(wake.At) {
		return false
	}
	return w.wakes.takeEarly(key, wake.At, w.period)
}

// anyTicks reports whether a heartbeat wake is due from any stream at now.
func (w *Watcher) anyTicks(now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, s := range w.svcs {
		if s.ticks(now) {
			return true
		}
	}
	return false
}

// LogWaitWoken logs a reconnect wait for key that a wake of kind ended, overdue
// past its wall deadline (negative when the wake came before it), instead of
// its timer.
func LogWaitWoken(key WaitKey, overdue time.Duration, kind WakeKind) {
	log.Debugf("hbwatch: retry wait ended by wake key=%s overdue=%d wake=%s", key, overdue.Milliseconds(), kind)
}

// WaitRetryDelay waits on the default Watcher. Without one it is a plain timer
// that netChanged cuts short.
func WaitRetryDelay(ctx context.Context, key WaitKey, d time.Duration, netChanged <-chan struct{}) error {
	if w := def(); w != nil {
		return w.WaitRetryDelay(ctx, key, d, netChanged)
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

// OnWake registers f on the default Watcher. Without one no wake comes and
// unsubscribe is a no-op.
func OnWake(f func(Wake)) (unsubscribe func()) {
	if w := def(); w != nil {
		return w.OnWake(f)
	}
	return func() {}
}

// WallNow returns the wall time of the default Watcher, or of the system clock
// without one. It carries no monotonic reading.
func WallNow() time.Time {
	if w := def(); w != nil {
		return w.now()
	}
	return time.Now().Round(0)
}
