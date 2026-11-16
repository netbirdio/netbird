package hbwatch

import (
	"context"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// debugLogs captures log entries down to debug level.
func debugLogs(t *testing.T) func(parts ...string) []string {
	t.Helper()
	hook := captureLogs(t)
	level := log.GetLevel()
	log.SetLevel(log.DebugLevel)
	t.Cleanup(func() { log.SetLevel(level) })
	return func(parts ...string) []string {
		return lines(hook, "hbwatch: retry wait ended by wake", parts...)
	}
}

// startWait runs WaitRetryDelay on w in the background and returns the channel
// its result lands on.
func startWait(t *testing.T, w *Watcher, key WaitKey, d time.Duration, netChanged <-chan struct{}) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		done <- w.WaitRetryDelay(ctx, key, d, netChanged)
	}()
	// Let the wait take its deadline before the test moves the clock.
	time.Sleep(20 * time.Millisecond)
	return done
}

func ended(done <-chan error, within time.Duration) (error, bool) {
	select {
	case err := <-done:
		return err, true
	case <-time.After(within):
		return nil, false
	}
}

// The phone slept: the wall clock went on, the timer did not. The first
// heartbeat of the next tick ends the wait.
func TestWaitRetryDelayEndsAtBurst(t *testing.T) {
	logs := debugLogs(t)
	clk := newFakeClock()
	w := New(clk, time.Minute)
	w.staleOn = func() bool { return false }
	w.Seen(Signal, Heartbeat{Period: time.Minute})

	done := startWait(t, w, WaitSync, 10*time.Second, nil)
	clk.advance(3 * time.Minute)
	_, ok := ended(done, 100*time.Millisecond)
	require.False(t, ok, "no wake yet, the wait must go on")

	w.Seen(Signal, Heartbeat{Period: time.Minute})
	err, ok := ended(done, time.Second)
	require.True(t, ok, "the burst must end an overdue wait")
	assert.NoError(t, err)
	assert.Len(t, logs("key=sync", "overdue=170000", "wake=burst"), 1, "one debug line with key, overdue ms and wake kind")
}

// A device wake ends an overdue wait too.
func TestWaitRetryDelayEndsAtDeviceWake(t *testing.T) {
	logs := debugLogs(t)
	clk := newFakeClock()
	w := New(clk, time.Minute)
	w.SetDeviceAsleep(true)

	done := startWait(t, w, WaitRelay, 30*time.Second, nil)
	clk.advance(3 * time.Minute)
	w.SetDeviceAsleep(false)
	err, ok := ended(done, time.Second)
	require.True(t, ok, "the device wake must end an overdue wait")
	assert.NoError(t, err)
	assert.Len(t, logs("key=relay", "overdue=150000", "wake=device"), 1)

	// CheckNow is the other device wake.
	done = startWait(t, w, WaitSignalReceive, 30*time.Second, nil)
	clk.advance(time.Minute)
	w.CheckNow()
	_, ok = ended(done, time.Second)
	assert.True(t, ok, "CheckNow must end an overdue wait")
}

// A wake before the wall deadline leaves the wait running; the next wake past
// it ends it.
func TestWaitRetryDelayWakeBeforeDeadline(t *testing.T) {
	logs := debugLogs(t)
	clk := newFakeClock()
	w := New(clk, time.Minute)

	done := startWait(t, w, WaitJob, 10*time.Second, nil)
	clk.advance(5 * time.Second)
	w.SetDeviceAsleep(false)
	_, ok := ended(done, 100*time.Millisecond)
	assert.False(t, ok, "a wake 5 s into a 10 s wait must not end it")
	assert.Empty(t, logs(), "no wake line while the wait goes on")

	clk.advance(6 * time.Second)
	w.SetDeviceAsleep(false)
	_, ok = ended(done, time.Second)
	assert.True(t, ok, "the wake past the deadline ends it")
	assert.Len(t, logs("key=job", "overdue=1000"), 1)
}

// A wall clock that went back must not hold the retry: the timer still ends
// the wait, and wakes before the shifted deadline do nothing.
func TestWaitRetryDelayClockBack(t *testing.T) {
	logs := debugLogs(t)
	clk := newFakeClock()
	w := New(clk, time.Minute)

	done := startWait(t, w, WaitSync, 200*time.Millisecond, nil)
	clk.mu.Lock()
	clk.now = clk.now.Add(-time.Hour)
	clk.mu.Unlock()
	w.SetDeviceAsleep(false)
	err, ok := ended(done, 2*time.Second)
	require.True(t, ok, "the timer must end the wait after the clock went back")
	assert.NoError(t, err)
	assert.Empty(t, logs(), "the timer, not a wake, ended it")
}

func TestWaitRetryDelayNetChangeAndCancel(t *testing.T) {
	clk := newFakeClock()
	w := New(clk, time.Minute)

	changed := make(chan struct{})
	done := startWait(t, w, WaitSync, time.Hour, changed)
	close(changed)
	err, ok := ended(done, time.Second)
	require.True(t, ok, "a network change must end the wait")
	assert.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	assert.ErrorIs(t, w.WaitRetryDelay(ctx, WaitSync, time.Hour, nil), context.Canceled)
}

// Without a Watcher the wait is a plain timer, as stock.
func TestWaitRetryDelayWithoutWatcher(t *testing.T) {
	t.Cleanup(SetDefault(nil))

	start := time.Now()
	require.NoError(t, WaitRetryDelay(context.Background(), WaitSync, 100*time.Millisecond, nil))
	assert.GreaterOrEqual(t, time.Since(start), 100*time.Millisecond, "the timer runs out in full")

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	CheckNow()
	SetDeviceAsleep(false)
	assert.ErrorIs(t, WaitRetryDelay(ctx, WaitSync, time.Hour, nil), context.DeadlineExceeded,
		"no wake source, so nothing but the timer, a network change or ctx ends it")

	unsubscribe := OnWake(func(Wake) {})
	unsubscribe()
}

type wakeLog struct {
	mu    sync.Mutex
	wakes []Wake
}

func (l *wakeLog) record(w Wake) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.wakes = append(l.wakes, w)
}

func (l *wakeLog) kinds() []WakeKind {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []WakeKind
	for _, w := range l.wakes {
		out = append(out, w.Kind)
	}
	return out
}

// Subscribers see one burst per tick and every device wake, but not a sleep.
func TestOnWakeKinds(t *testing.T) {
	clk := newFakeClock()
	w := New(clk, time.Minute)
	w.staleOn = func() bool { return false }
	l := &wakeLog{}
	unsubscribe := w.OnWake(l.record)

	w.Seen(Signal, Heartbeat{Period: time.Minute})
	w.Seen(Relay, Heartbeat{Period: time.Minute})
	w.SetDeviceAsleep(true)
	w.SetDeviceAsleep(false)
	w.CheckNow()
	assert.Equal(t, []WakeKind{WakeBurst, WakeDevice, WakeDevice}, l.kinds(),
		"one burst for the tick, a device wake each for SetDeviceAsleep(false) and CheckNow")

	unsubscribe()
	clk.advance(time.Minute)
	w.Seen(Signal, Heartbeat{Period: time.Minute})
	assert.Len(t, l.kinds(), 3, "no wake after unsubscribe")
}
