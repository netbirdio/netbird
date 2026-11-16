package hbwatch

import (
	"context"
	"sync"
	"time"
)

// FastRetryWindow is how long after a Management drop the client retries on
// the stock backoff whatever the device state. It covers a server restart.
const FastRetryWindow = 30 * time.Second

// awakeHold is how long the device must stay awake before the gate treats it
// as awake. A peer keepalive wakes an iPhone for about 3 s, and iOS reports
// each such wake like any other, so a short wake counts as one more wake of a
// sleeping device.
const awakeHold = 30 * time.Second

// RetryKey names what the gate limits to one attempt per period: a Management
// stream, or the dials of the Management connection.
type RetryKey string

const (
	// RetrySync and RetryJob are the Management streams.
	RetrySync RetryKey = "sync"
	RetryJob  RetryKey = "job"
	// RetryDial is the gRPC channel redialing the Management server.
	RetryDial RetryKey = "dial"
)

// retryGate holds Management reconnects on a locked, idle device until a wake
// the device has anyway: the Signal and relay heartbeat burst or a device
// wake. Tunnels and new peer connections keep working while Management is
// gone, only network map updates wait, so a retry is not worth its own wake.
type retryGate struct {
	mu sync.Mutex
	// asleep is set by the app when the device goes to sleep, cleared when it
	// wakes. A device the app never reported asleep counts as awake.
	asleep bool
	// awakeSince is when the device last woke from a reported sleep, zero
	// while asleep or when no sleep was ever reported.
	awakeSince time.Time
	// lastWake is the last heartbeat tick or device wake.
	lastWake time.Time
	// woke is closed and replaced on every wake and state change.
	woke chan struct{}
	// lastRetry is the wake of the last attempt the gate let through, per key.
	lastRetry map[RetryKey]time.Time

	// activity returns a stamp of the newest real tunnel traffic, keepalives
	// and handshakes excluded, ok false when unknown. Only changes of the stamp
	// count: its clock may stand still while the device sleeps.
	activity func() (stamp int64, ok bool)
	probeID  uint64
	// lastStamp is the stamp sampled at the previous wake, valid when hasStamp.
	lastStamp int64
	hasStamp  bool
	// flowing is set when the stamp moved between the last two wakes.
	flowing bool
}

func newRetryGate() *retryGate {
	return &retryGate{woke: make(chan struct{}), lastRetry: map[RetryKey]time.Time{}}
}

// signal wakes the waiting retries. Caller holds g.mu.
func (g *retryGate) signal() {
	close(g.woke)
	g.woke = make(chan struct{})
}

// recheck wakes the waiting retries without recording a wake, so they decide
// again on a changed set of ticking streams.
func (g *retryGate) recheck() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.signal()
}

// wake records a heartbeat tick or a device wake at now, and samples the
// tunnel activity.
func (g *retryGate) wake(now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lastWake = now
	g.sampleActivity()
	g.signal()
}

// sampleActivity reads the activity stamp and sets flowing when it moved since
// the previous wake. Caller holds g.mu.
func (g *retryGate) sampleActivity() {
	if g.activity == nil {
		g.flowing, g.hasStamp = false, false
		return
	}
	stamp, ok := g.activity()
	if !ok {
		g.flowing, g.hasStamp = false, false
		return
	}
	g.flowing = g.hasStamp && stamp != g.lastStamp
	g.lastStamp, g.hasStamp = stamp, true
}

// setAsleep records the device sleep state the app reported. woke reports
// whether the device left a reported sleep.
func (g *retryGate) setAsleep(asleep bool, now time.Time) (woke bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	woke = g.asleep && !asleep
	g.asleep = asleep
	switch {
	case asleep:
		g.awakeSince = time.Time{}
	case woke:
		g.awakeSince = now
	}
	if !asleep {
		g.lastWake = now
	}
	g.signal()
	return woke
}

// sleepy reports whether the device sleeps or woke less than awakeHold before
// now. Caller holds g.mu.
func (g *retryGate) sleepy(now time.Time) bool {
	if g.asleep {
		return true
	}
	return !g.awakeSince.IsZero() && now.Sub(g.awakeSince) < awakeHold
}

// setActivity sets the tunnel activity probe and returns the func that
// removes it. The remove func is a no-op once a newer probe was set.
func (g *retryGate) setActivity(f func() (int64, bool)) (remove func()) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.probeID++
	id := g.probeID
	g.activity = f
	g.flowing, g.hasStamp = false, false
	return func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		if g.probeID == id {
			g.activity = nil
			g.flowing, g.hasStamp = false, false
		}
	}
}

// retryInput is what the gate needs from the Watcher for one decision.
type retryInput struct {
	key       RetryKey
	now       time.Time
	downSince time.Time
	period    time.Duration
	// ticking is set when a Signal or relay stream got heartbeats or opened
	// aligned, so a heartbeat wake will come.
	ticking bool
}

// holding reports whether attempts are held at all at in, regardless of
// wakes. Traffic counts as flowing from the activity sampled at wakes. Caller
// holds g.mu.
func (g *retryGate) holding(in retryInput) bool {
	return in.now.Sub(in.downSince) >= FastRetryWindow && in.ticking && g.sleepy(in.now) && !g.flowing
}

// waitChan returns the channel that the next wake or state change closes.
// Take it before the inputs of a decision, so a change between the two closes
// it and the caller decides again.
func (g *retryGate) waitChan() <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.woke
}

// decide reports whether an attempt for in.key may go now. When not, the
// caller waits on the channel it took from waitChan before it read in. held
// reports whether the gate holds attempts, so a caller that goes inside a wake
// knows it was held.
func (g *retryGate) decide(in retryInput) (allow, held bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.holding(in) {
		return true, false
	}
	inWake := !g.lastWake.IsZero() && in.now.Sub(g.lastWake) <= BurstDelay
	// Spacing is wake to wake: an attempt late in one burst must not block the
	// next burst for being a few seconds short of a period.
	last := g.lastRetry[in.key]
	spaced := last.IsZero() || g.lastWake.Sub(last) >= in.period-Tolerance
	if inWake && spaced {
		g.lastRetry[in.key] = g.lastWake
		return true, true
	}
	return false, true
}

// retryInput returns the inputs of a decision for key on a Management
// connection down since downSince.
func (w *Watcher) retryInput(key RetryKey, downSince time.Time) retryInput {
	w.mu.Lock()
	defer w.mu.Unlock()
	period := w.mgmtPeriod
	if period <= 0 {
		period = w.period
	}
	now := w.now()
	ticking := w.svcs[Signal].ticks(now) || w.svcs[Relay].ticks(now)
	return retryInput{key: key, now: now, downSince: downSince, period: period, ticking: ticking}
}

// WaitManagementRetry blocks an attempt for key on a Management connection
// down since downSince until it may go. The first FastRetryWindow after the
// drop, once the device stayed awake for awakeHold, while the tunnel carries
// real traffic, and without a ticking Signal or relay stream, it returns at
// once: the stock backoff applies. Otherwise it waits for a wake the device
// has anyway and lets at most one attempt per key through per period. A
// network change on netChanged releases it at once. waited reports whether
// it held the attempt. It returns ctx.Err() when ctx is done.
func (w *Watcher) WaitManagementRetry(ctx context.Context, key RetryKey, downSince time.Time, netChanged <-chan struct{}) (waited bool, err error) {
	for {
		// The channel is taken before the inputs: a recheck between the two,
		// as when the last ticking stream drops, closes it.
		woke := w.gate.waitChan()
		allow, held := w.gate.decide(w.retryInput(key, downSince))
		if allow {
			return waited || held, nil
		}
		waited = true
		select {
		case <-ctx.Done():
			return true, ctx.Err()
		case <-netChanged:
			return true, nil
		case <-woke:
		}
	}
}

// SetDeviceAsleep records whether the device sleeps, as the app reports it.
// A wake also ends the reconnect waits whose wall deadline passed. A device
// still awake awakeHold after the wake gets the stock backoff, so the gate
// decides again then.
func (w *Watcher) SetDeviceAsleep(asleep bool) {
	now := w.now()
	if w.gate.setAsleep(asleep, now) {
		w.clk.AfterFunc(awakeHold, w.gate.recheck)
	}
	if asleep {
		w.wakes.sleep(now)
		return
	}
	w.wakes.fire(Wake{Kind: WakeDevice, At: now})
}

// SetTunnelActivity sets the function that returns a stamp of the newest real
// tunnel traffic. Traffic counts as flowing when the stamp moved between two
// wakes. The returned func removes it.
func (w *Watcher) SetTunnelActivity(f func() (stamp int64, ok bool)) (remove func()) {
	return w.gate.setActivity(f)
}

// WaitManagementRetry waits on the default Watcher. Without one it returns at
// once.
func WaitManagementRetry(ctx context.Context, key RetryKey, downSince time.Time, netChanged <-chan struct{}) (waited bool, err error) {
	if w := def(); w != nil {
		return w.WaitManagementRetry(ctx, key, downSince, netChanged)
	}
	return false, nil
}

// SetDeviceAsleep records the device sleep state on the default Watcher.
// No-op without one.
func SetDeviceAsleep(asleep bool) {
	if w := def(); w != nil {
		w.SetDeviceAsleep(asleep)
	}
}

// SetTunnelActivity sets the tunnel activity probe on the default Watcher. The
// returned func removes it. No-op without one.
func SetTunnelActivity(f func() (stamp int64, ok bool)) (remove func()) {
	if w := def(); w != nil {
		return w.SetTunnelActivity(f)
	}
	return func() {}
}
