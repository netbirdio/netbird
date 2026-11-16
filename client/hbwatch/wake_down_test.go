package hbwatch

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// All streams are down, so no burst will come. The device sleeps during the
// relay retry wait and wakes before the wall deadline: the wake is the only
// chance to reconnect, so it ends the wait.
func TestWaitRetryDelayEndsAtDeviceWakeWhileNothingTicks(t *testing.T) {
	logs := debugLogs(t)
	clk := newFakeClock()
	w := New(clk, time.Minute)

	done := startWait(t, w, WaitRelay, 60*time.Second, nil)
	clk.advance(time.Second)
	w.SetDeviceAsleep(true)
	clk.advance(20 * time.Second)
	w.SetDeviceAsleep(false)
	err, ok := ended(done, time.Second)
	require.True(t, ok, "the device wake after a sleep must end the wait while no stream ticks")
	assert.NoError(t, err)
	assert.Len(t, logs("key=relay", "overdue=-39000", "wake=device"), 1, "the line shows the wait ended 39 s early")

	// The same for Signal, here through CheckNow, the other device wake.
	done = startWait(t, w, WaitSignalReceive, 20*time.Second, nil)
	clk.advance(time.Second)
	w.SetDeviceAsleep(true)
	clk.advance(5 * time.Second)
	w.CheckNow()
	_, ok = ended(done, time.Second)
	assert.True(t, ok, "CheckNow after a sleep must end the Signal wait while no stream ticks")
}

// While a stream ticks, bursts come, so a device wake before the wall deadline
// leaves the wait running as before.
func TestWaitRetryDelayKeepsWaitWhileStreamTicks(t *testing.T) {
	logs := debugLogs(t)
	clk := newFakeClock()
	w := New(clk, time.Minute)
	w.staleOn = func() bool { return false }
	w.Register(Signal, Registration{Stale: func() {}})
	w.Seen(Signal, Heartbeat{Period: time.Minute})

	done := startWait(t, w, WaitRelay, 60*time.Second, nil)
	clk.advance(time.Second)
	w.SetDeviceAsleep(true)
	clk.advance(20 * time.Second)
	w.SetDeviceAsleep(false)
	_, ok := ended(done, 100*time.Millisecond)
	assert.False(t, ok, "a ticking Signal stream keeps the wait until its deadline")
	assert.Empty(t, logs(), "no wake line while the wait goes on")
}

// A wake with no sleep reported during the wait, such as a second wake in the
// same awake time, leaves the wait running.
func TestWaitRetryDelayKeepsWaitWithoutSleep(t *testing.T) {
	clk := newFakeClock()
	w := New(clk, time.Minute)
	w.SetDeviceAsleep(true)
	clk.advance(time.Second)
	w.SetDeviceAsleep(false)

	done := startWait(t, w, WaitRelay, 60*time.Second, nil)
	clk.advance(5 * time.Second)
	w.SetDeviceAsleep(false)
	w.CheckNow()
	_, ok := ended(done, 100*time.Millisecond)
	assert.False(t, ok, "the device slept before the wait started, not during it")
}
