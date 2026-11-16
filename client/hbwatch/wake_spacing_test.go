package hbwatch

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// keepaliveEvery is the peer keepalive that wakes a locked iPhone with
	// permanent links.
	keepaliveEvery = 25 * time.Second
	// keepaliveAwake is how long the extension stays awake after such a wake.
	keepaliveAwake = 3 * time.Second
	spacingPeriod  = time.Minute
	settle         = 20 * time.Millisecond
)

// attemptLog records the wall time of every attempt per key.
type attemptLog struct {
	mu sync.Mutex
	at map[string][]time.Time
}

func newAttemptLog() *attemptLog {
	return &attemptLog{at: map[string][]time.Time{}}
}

func (l *attemptLog) add(key string, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.at[key] = append(l.at[key], at)
}

// since returns the attempts for key at or after from.
func (l *attemptLog) since(key string, from time.Time) []time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []time.Time
	for _, at := range l.at[key] {
		if !at.Before(from) {
			out = append(out, at)
		}
	}
	return out
}

// assertSpaced checks that attempts for key at or after from come at most once
// per period, wake to wake, and that there are at most maxCount of them.
func assertSpaced(t *testing.T, l *attemptLog, key string, from time.Time, maxCount int) {
	t.Helper()
	got := l.since(key, from)
	require.NotEmpty(t, got, "key %s must still get attempts", key)
	t.Logf("key %s: %d attempts", key, len(got))
	assert.LessOrEqual(t, len(got), maxCount, "key %s: at most one attempt per period, got %v", key, got)
	for i := 1; i < len(got); i++ {
		gap := got[i].Sub(got[i-1])
		assert.GreaterOrEqual(t, gap, spacingPeriod-Tolerance, "key %s: attempts %d and %d only %s apart", key, i-1, i, gap)
	}
}

// spacingRig is a watcher with a 60 s period on a phone that sleeps between
// wakes.
type spacingRig struct {
	clk *fakeClock
	w   *Watcher
}

func newSpacingRig(t *testing.T) *spacingRig {
	t.Helper()
	captureLogs(t)
	clk := newFakeClock()
	w := New(clk, spacingPeriod)
	w.staleOn = func() bool { return false }
	return &spacingRig{clk: clk, w: w}
}

// tick registers Signal and relay on first use and delivers their heartbeats.
func (r *spacingRig) tick() {
	for _, svc := range []Service{Signal, Relay} {
		r.w.Seen(svc, Heartbeat{Period: spacingPeriod})
	}
}

func (r *spacingRig) registerTicking() {
	for _, svc := range []Service{Signal, Relay} {
		r.w.Register(svc, Registration{Kind: ActionReconnect, Stale: func() {}, Correct: func(time.Duration) {}})
	}
}

// wakeCycle is one device wake as the iOS extension reports it: wake() calls
// DeviceAwake and CheckHeartbeatsNow, sleep() follows keepaliveAwake later.
func (r *spacingRig) wakeCycle() {
	r.w.SetDeviceAsleep(false)
	r.w.CheckNow()
	time.Sleep(settle)
	r.clk.advance(keepaliveAwake)
	time.Sleep(settle)
	r.w.SetDeviceAsleep(true)
}

// run drives the phone from start for d: a heartbeat burst with a device wake
// every period when bursts is set, and a keepalive device wake every 25 s.
func (r *spacingRig) run(start time.Time, d time.Duration, bursts bool) {
	nextBurst := start
	nextKA := start.Add(keepaliveEvery / 2)
	end := start.Add(d)
	for {
		at := nextKA
		burst := bursts && !nextBurst.After(nextKA)
		if burst {
			at = nextBurst
		}
		if at.After(end) {
			return
		}
		r.clk.advanceTo(at)
		if burst {
			r.tick()
			nextBurst = nextBurst.Add(spacingPeriod)
		} else {
			nextKA = nextKA.Add(keepaliveEvery)
		}
		r.wakeCycle()
	}
}

// mgmtLoop runs the Management retry loop of key as withMgmtStream does: the
// gate, then an attempt that fails, then the stock backoff wait (at most 10 s).
func (r *spacingRig) mgmtLoop(ctx context.Context, key RetryKey, down time.Time, l *attemptLog) {
	go func() {
		for {
			if _, err := r.w.WaitManagementRetry(ctx, key, down, nil); err != nil {
				return
			}
			l.add(string(key), r.w.now())
			if err := r.w.WaitRetryDelay(ctx, WaitKey(key), 10*time.Second, nil); err != nil {
				return
			}
		}
	}()
}

// Permanent links on a locked iPhone: the peer keepalive wakes the device
// every 25 s while Management is down and Signal and relay tick. Each key
// still gets at most one attempt per period past the fast window.
func TestRetryKeepaliveWakesSpacedPerKey(t *testing.T) {
	r := newSpacingRig(t)
	r.registerTicking()
	r.tick()
	r.w.SetDeviceAsleep(true)
	down := r.w.now().Add(time.Second)
	r.clk.advanceTo(down)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l := newAttemptLog()
	keys := []RetryKey{RetrySync, RetryJob, RetryDial}
	for _, k := range keys {
		r.mgmtLoop(ctx, k, down, l)
	}
	time.Sleep(settle)

	r.run(down.Add(-time.Second).Add(spacingPeriod), 5*time.Minute, true)
	time.Sleep(settle)

	for _, k := range keys {
		assertSpaced(t, l, string(k), down.Add(FastRetryWindow), 6)
	}
}

// The fast window after the drop keeps its attempts: every keepalive wake in
// it lets each key through.
func TestRetryKeepaliveWakesInFastWindow(t *testing.T) {
	r := newSpacingRig(t)
	r.registerTicking()
	r.tick()
	r.w.SetDeviceAsleep(true)
	down := r.w.now().Add(time.Second)
	r.clk.advanceTo(down)

	// Three wake cycles of 8 s end 24 s after the drop, inside the window.
	for i := 0; i < 3; i++ {
		r.clk.advance(5 * time.Second)
		r.wakeCycle()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		waited, err := r.w.WaitManagementRetry(ctx, RetrySync, down, nil)
		cancel()
		require.NoError(t, err)
		assert.False(t, waited, "attempt %d inside the fast window goes at once", i)
	}
}

// A device that stays awake, screen on, gets the stock backoff once it was
// awake for awakeHold: a held attempt goes without a new wake.
func TestRetryLongAwakeReleases(t *testing.T) {
	r := newSpacingRig(t)
	r.registerTicking()
	r.tick()
	r.w.SetDeviceAsleep(true)
	down := r.w.now().Add(time.Second)
	r.clk.advanceTo(down.Add(FastRetryWindow + time.Second))

	r.w.SetDeviceAsleep(false)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	_, err := r.w.WaitManagementRetry(ctx, RetrySync, down, nil)
	require.NoError(t, err, "the device wake lets the first attempt through")

	r.clk.advance(10 * time.Second)
	done := make(chan struct{})
	go func() {
		if _, err := r.w.WaitManagementRetry(ctx, RetrySync, down, nil); err == nil {
			close(done)
		}
	}()
	select {
	case <-done:
		t.Fatal("a second attempt 10 s into the wake is held")
	case <-time.After(50 * time.Millisecond):
	}

	r.clk.advance(awakeHold)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a device awake past awakeHold must get the stock backoff")
	}
}

// All streams down, so nothing ticks and a retry wait ends at a device wake
// after a sleep. Keepalive wakes every 25 s must not end a long wait at each
// of them: at most one early end per key per period.
func TestWaitRetryDelayKeepaliveWakesSpacedPerKey(t *testing.T) {
	r := newSpacingRig(t)
	start := r.w.now()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	l := newAttemptLog()
	for _, k := range []WaitKey{WaitRelay, WaitSignalReceive} {
		go func(key WaitKey) {
			for {
				if err := r.w.WaitRetryDelay(ctx, key, 90*time.Second, nil); err != nil {
					return
				}
				l.add(string(key), r.w.now())
			}
		}(k)
	}
	time.Sleep(settle)
	// The device goes to sleep after the waits started.
	r.clk.advance(500 * time.Millisecond)
	r.w.SetDeviceAsleep(true)

	r.run(start.Add(time.Second), 5*time.Minute, false)
	time.Sleep(settle)

	for _, k := range []WaitKey{WaitRelay, WaitSignalReceive} {
		got := l.since(string(k), start)
		require.NotEmpty(t, got, "key %s: the first wake after a sleep still ends the wait", k)
		assert.Equal(t, start.Add(keepaliveEvery/2+time.Second), got[0], "key %s: the first early end is at the first wake", k)
		assertSpaced(t, l, string(k), start, 6)
	}
}
