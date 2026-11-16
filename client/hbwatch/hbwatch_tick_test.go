package hbwatch

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type tickLog struct {
	mu      sync.Mutex
	periods []time.Duration
}

func (l *tickLog) record(period time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.periods = append(l.periods, period)
}

func (l *tickLog) get() []time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]time.Duration(nil), l.periods...)
}

func newTickWatcher(t *testing.T) (*fakeClock, *Watcher, *tickLog) {
	t.Helper()
	captureLogs(t)
	clk := newFakeClock()
	w := New(clk, time.Minute)
	w.staleOn = func() bool { return false }
	l := &tickLog{}
	unsubscribe := w.OnTick(l.record)
	t.Cleanup(unsubscribe)
	return clk, w, l
}

// The three streams of one tick land within a few seconds: one tick. The next
// period starts the next tick, whichever stream lands first.
func TestTickOncePerPeriod(t *testing.T) {
	clk, w, l := newTickWatcher(t)
	hb := Heartbeat{Period: time.Minute}

	w.Seen(Management, hb)
	clk.advance(2 * time.Second)
	w.Seen(Signal, hb)
	clk.advance(3 * time.Second)
	w.Seen(Relay, hb)
	assert.Equal(t, []time.Duration{time.Minute}, l.get(), "one tick for the streams of one period")

	clk.advance(55 * time.Second)
	w.Seen(Relay, hb)
	clk.advance(time.Second)
	w.Seen(Management, hb)
	assert.Equal(t, []time.Duration{time.Minute, time.Minute}, l.get(), "second period starts a second tick")
}

// With stale checks on, the tick still fires once per period.
func TestTickWithStaleCheckOn(t *testing.T) {
	clk, w, l := newTickWatcher(t)
	w.staleOn = func() bool { return true }
	hb := Heartbeat{Period: time.Minute}

	w.Seen(Management, hb)
	w.Seen(Signal, hb)
	clk.advance(time.Minute)
	w.Seen(Signal, hb)
	assert.Len(t, l.get(), 2, "one tick per period with stale checks on")
}

// A heartbeat without a period uses the watcher period to group the tick.
func TestTickZeroPeriodUsesWatcherPeriod(t *testing.T) {
	clk, w, l := newTickWatcher(t)

	w.Seen(Relay, Heartbeat{})
	clk.advance(20 * time.Second)
	w.Seen(Relay, Heartbeat{})
	assert.Equal(t, []time.Duration{time.Minute}, l.get(), "20 s is under half the watcher period")

	clk.advance(40 * time.Second)
	w.Seen(Relay, Heartbeat{})
	assert.Len(t, l.get(), 2, "a full period later is a new tick")
}

// A wall clock that went back must not hold the ticks back until it catches up.
func TestTickClockBack(t *testing.T) {
	clk, w, l := newTickWatcher(t)
	hb := Heartbeat{Period: time.Minute}

	clk.advance(10 * time.Minute)
	w.Seen(Management, hb)
	clk.mu.Lock()
	clk.now = clk.now.Add(-5 * time.Minute)
	clk.mu.Unlock()
	w.Seen(Management, hb)
	assert.Len(t, l.get(), 2, "a heartbeat before the last tick starts a new tick")
}

func TestTickUnsubscribe(t *testing.T) {
	clk, w, l := newTickWatcher(t)
	other := &tickLog{}
	unsubscribe := w.OnTick(other.record)
	hb := Heartbeat{Period: time.Minute}

	w.Seen(Management, hb)
	unsubscribe()
	clk.advance(time.Minute)
	w.Seen(Management, hb)

	assert.Len(t, other.get(), 1, "no tick after unsubscribe")
	assert.Len(t, l.get(), 2, "other subscribers keep their ticks")
}

// The default watcher only exists on builds that ask for the aligned heartbeat.
func TestOnTickWithoutWatcher(t *testing.T) {
	restore := SetDefault(nil)
	t.Cleanup(restore)

	unsubscribe, ok := OnTick(func(time.Duration) {})
	require.NotNil(t, unsubscribe)
	assert.False(t, ok, "no watcher means no tick")
	unsubscribe()
}

func TestOnTickDefaultWatcher(t *testing.T) {
	clk, w, l := newTickWatcher(t)
	restore := SetDefault(w)
	t.Cleanup(restore)

	other := &tickLog{}
	unsubscribe, ok := OnTick(other.record)
	t.Cleanup(unsubscribe)
	require.True(t, ok, "default watcher set")

	Seen(Signal, Heartbeat{Period: 90 * time.Second})
	clk.advance(time.Second)
	assert.Equal(t, []time.Duration{90 * time.Second}, other.get(), "tick carries the heartbeat period")
	assert.Len(t, l.get(), 1)
}
