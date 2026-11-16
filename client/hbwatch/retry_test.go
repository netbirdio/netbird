package hbwatch

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/alignedhb"
)

// retryRig is a watcher with aligned Signal and relay streams and a Management
// stream that dropped at down.
type retryRig struct {
	clk  *fakeClock
	w    *Watcher
	down time.Time
}

func newRetryRig(t *testing.T) *retryRig {
	t.Helper()
	captureLogs(t)
	clk, w, _, _ := setup(t)
	heartbeats(clk, w, tickAt(1), onTime...)
	clk.advanceTo(tickAt(1).Add(time.Second))
	return &retryRig{clk: clk, w: w, down: clk.Now()}
}

// try runs one gated attempt and reports whether it went within a short real
// wait. A held attempt is left waiting in the background; release reports
// when it goes.
func (r *retryRig) try(t *testing.T, netChanged <-chan struct{}) (went bool, release <-chan struct{}) {
	t.Helper()
	return r.tryKey(t, RetrySync, netChanged)
}

func (r *retryRig) tryKey(t *testing.T, key RetryKey, netChanged <-chan struct{}) (went bool, release <-chan struct{}) {
	t.Helper()
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		if _, err := r.w.WaitManagementRetry(ctx, key, r.down, netChanged); err == nil {
			close(done)
		}
	}()
	select {
	case <-done:
		return true, done
	case <-time.After(50 * time.Millisecond):
		return false, done
	}
}

func released(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	case <-time.After(time.Second):
		return false
	}
}

// Stock behaviour: an awake device, or one the app never reported asleep,
// retries on the stock backoff.
func TestRetryAwakeDeviceNotHeld(t *testing.T) {
	r := newRetryRig(t)
	r.clk.advance(2 * time.Minute)
	went, _ := r.try(t, nil)
	assert.True(t, went, "a device not reported asleep must retry at once")
}

// The first 30 s after the drop retry fast even on a sleeping device: that
// covers a server restart.
func TestRetryFastWindow(t *testing.T) {
	r := newRetryRig(t)
	r.w.SetDeviceAsleep(true)
	r.clk.advance(FastRetryWindow - time.Second)
	went, _ := r.try(t, nil)
	assert.True(t, went, "inside the fast window")

	r.clk.advance(2 * time.Second)
	went, _ = r.try(t, nil)
	assert.False(t, went, "past the fast window a sleeping idle device holds the retry")
}

// A held retry goes with the next heartbeat burst, and at most once per period
// even when wakes come more often.
func TestRetryInsideWakeOncePerPeriod(t *testing.T) {
	r := newRetryRig(t)
	r.down = r.down.Add(-time.Minute)
	r.w.SetDeviceAsleep(true)
	r.clk.advanceTo(tickAt(2).Add(-time.Second))

	went, release := r.try(t, nil)
	require.False(t, went, "held until a wake")
	r.clk.advanceTo(tickAt(2))
	r.w.Seen(Signal, beat)
	assert.True(t, released(release), "the heartbeat burst lets the retry through")

	// A device wake 10 s later is inside the same period.
	r.clk.advanceTo(tickAt(2).Add(10 * time.Second))
	r.w.CheckNow()
	went, release = r.try(t, nil)
	assert.False(t, went, "a second retry in the same period is held")

	r.clk.advanceTo(tickAt(3))
	r.w.Seen(Signal, beat)
	assert.True(t, released(release), "the next period's burst lets it through")
}

// A network change retries at once, as before.
func TestRetryNetworkChangeReleases(t *testing.T) {
	r := newRetryRig(t)
	r.w.SetDeviceAsleep(true)
	r.clk.advance(time.Minute)
	changed := make(chan struct{})
	went, release := r.try(t, changed)
	require.False(t, went, "held")
	close(changed)
	assert.True(t, released(release), "a network change releases the retry")
}

// The app reporting the device awake releases a held retry.
func TestRetryDeviceWakeReleases(t *testing.T) {
	r := newRetryRig(t)
	r.w.SetDeviceAsleep(true)
	r.clk.advance(time.Minute)
	went, release := r.try(t, nil)
	require.False(t, went, "held")
	r.w.SetDeviceAsleep(false)
	assert.True(t, released(release), "device awake releases the retry")
}

// Real traffic through the tunnel keeps the radio on anyway: stock retries.
// Traffic counts only when the activity stamp moved between two wakes, so a
// stamp whose clock stood still while the phone slept, or one that only
// keepalives would leave alone, keeps the retry held.
func TestRetryTrafficNotHeld(t *testing.T) {
	r := newRetryRig(t)
	r.down = r.down.Add(-time.Minute)
	r.w.SetDeviceAsleep(true)
	var stamp atomic.Int64
	stamp.Store(1000)
	remove := r.w.SetTunnelActivity(func() (int64, bool) { return stamp.Load(), true })

	// Several wakes with the same stamp: never traffic, however fresh the
	// stamp would look on a monotonic clock that stood still.
	for n := 2; n <= 4; n++ {
		r.clk.advanceTo(tickAt(n))
		r.w.CheckNow()
	}
	r.clk.advance(10 * time.Second)
	went, release := r.try(t, nil)
	require.False(t, went, "an unchanged stamp over several wakes keeps the retry held")

	stamp.Add(1)
	r.w.CheckNow()
	assert.True(t, released(release), "a moved stamp releases the retry")
	r.clk.advance(10 * time.Second)
	went, _ = r.try(t, nil)
	assert.True(t, went, "traffic seen at the last wake keeps retries stock")

	remove()
	r.w.CheckNow()
	r.clk.advance(10 * time.Second)
	went, _ = r.try(t, nil)
	assert.False(t, went, "without a probe traffic is unknown and the retry is held outside a wake")
}

// Sync and Job each get their attempt in the same wake: the once per period
// limit is per stream.
func TestRetryPerStreamInSameWake(t *testing.T) {
	r := newRetryRig(t)
	r.down = r.down.Add(-time.Minute)
	r.w.SetDeviceAsleep(true)
	r.clk.advanceTo(tickAt(2).Add(-time.Second))

	wentSync, releaseSync := r.tryKey(t, RetrySync, nil)
	wentJob, releaseJob := r.tryKey(t, RetryJob, nil)
	require.False(t, wentSync || wentJob, "both held until a wake")
	r.clk.advanceTo(tickAt(2))
	r.w.Seen(Signal, beat)
	assert.True(t, released(releaseSync), "sync goes in the wake")
	assert.True(t, released(releaseJob), "job goes in the same wake")
}

// Without an aligned Signal or relay stream no heartbeat wake will come, so
// nothing is held.
func TestRetryWithoutTickingStreamNotHeld(t *testing.T) {
	captureLogs(t)
	clk := newFakeClock()
	w := newTestWatcher(clk)
	w.SetDeviceAsleep(true)
	down := clk.Now()
	clk.advance(time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := w.WaitManagementRetry(ctx, RetrySync, down, nil)
	assert.NoError(t, err, "no aligned stream, stock retry")
}

// An older engine's remove func must not drop the probe of a newer one.
func TestTunnelActivityRemoveOnlyOwn(t *testing.T) {
	g := newRetryGate()
	removeOld := g.setActivity(func() (int64, bool) { return 1, true })
	var stamp atomic.Int64
	g.setActivity(func() (int64, bool) { return stamp.Add(1), true })
	removeOld()
	g.wake(time.Now())
	g.wake(time.Now())
	g.mu.Lock()
	defer g.mu.Unlock()
	assert.True(t, g.flowing, "the newer probe stays")
}

// reopen registers new Signal and relay streams at the current time, as after
// a server restart that cut every stream. period is the aligned period the
// servers confirmed at stream open, zero for a stock open.
func (r *retryRig) reopen(period time.Duration) (unregister func()) {
	var unreg []func()
	for _, svc := range []Service{Signal, Relay} {
		unreg = append(unreg, r.w.Register(svc, Registration{
			Kind: ActionReconnect, Stale: func() {}, Correct: func(time.Duration) {}, AlignedPeriod: period,
		}))
	}
	return func() {
		for _, f := range unreg {
			f()
		}
	}
}

// restartRig drops Management one second after tick 1 and reopens Signal and
// relay half a second later, with no heartbeat on the new streams yet.
func restartRig(t *testing.T, period time.Duration) (*retryRig, func()) {
	t.Helper()
	r := newRetryRig(t)
	r.w.SetDeviceAsleep(true)
	r.clk.advanceTo(r.down.Add(500 * time.Millisecond))
	return r, r.reopen(period)
}

// A server restart cuts Signal and relay too. Their new streams open aligned,
// but the first heartbeat comes up to a period later. Past the fast window
// the retry must wait for that heartbeat wake, not run the stock backoff.
func TestRetryHeldOnStreamsOpenedAligned(t *testing.T) {
	r, _ := restartRig(t, testPeriod)
	r.clk.advanceTo(r.down.Add(FastRetryWindow + time.Second))

	went, release := r.try(t, nil)
	require.False(t, went, "streams that opened aligned hold the retry before their first heartbeat")

	r.clk.advanceTo(tickAt(2).Add(4 * time.Second))
	r.w.Seen(Signal, beat)
	assert.True(t, released(release), "the first heartbeat on the new stream lets the retry through")
}

// A stream that opened stock, or without a phase, gives no heartbeat wake
// until its first heartbeat, so it holds nothing.
func TestRetryNotHeldOnStreamsOpenedStock(t *testing.T) {
	r, _ := restartRig(t, 0)
	r.clk.advanceTo(r.down.Add(FastRetryWindow + time.Second))

	went, _ := r.try(t, nil)
	assert.True(t, went, "a stream that opened stock must not hold the retry")
}

// A stream that opened aligned but sends no heartbeat within the receive
// timeout stops holding: the waiting retry goes without a wake.
func TestRetryReleasedWhenFirstHeartbeatOverdue(t *testing.T) {
	r, _ := restartRig(t, testPeriod)
	opened := r.clk.Now()
	r.clk.advanceTo(r.down.Add(FastRetryWindow + time.Second))

	went, release := r.try(t, nil)
	require.False(t, went, "held while the first heartbeat may still come")

	r.clk.advanceTo(opened.Add(alignedhb.ReceiveTimeout(testPeriod) + time.Second))
	assert.True(t, released(release), "an overdue first heartbeat releases the retry")
	went, _ = r.try(t, nil)
	assert.True(t, went, "later retries run the stock backoff")
}

// The overdue recheck must come after the receive timeout, not at it: at
// exactly the timeout the stream still counts as ticking, and a recheck there
// would leave the retry held with no later recheck.
func TestRetryOverdueRecheckAfterReceiveTimeout(t *testing.T) {
	r, _ := restartRig(t, testPeriod)
	opened := r.clk.Now()
	r.clk.advanceTo(r.down.Add(FastRetryWindow + time.Second))

	went, release := r.try(t, nil)
	require.False(t, went, "held while the first heartbeat may still come")

	r.clk.advanceTo(opened.Add(alignedhb.ReceiveTimeout(testPeriod)))
	select {
	case <-release:
		t.Fatal("at exactly the receive timeout the first heartbeat is not overdue yet")
	case <-time.After(50 * time.Millisecond):
	}

	r.clk.advanceTo(opened.Add(alignedhb.ReceiveTimeout(testPeriod) + overdueSlack))
	assert.True(t, released(release), "just past the receive timeout the recheck releases the retry")
}

// Signal and relay going away leave no heartbeat wake, so a held retry goes.
func TestRetryReleasedWhenTickingStreamsEnd(t *testing.T) {
	r, unregister := restartRig(t, testPeriod)
	r.clk.advanceTo(r.down.Add(FastRetryWindow + time.Second))

	went, release := r.try(t, nil)
	require.False(t, went, "held while the streams are up")

	unregister()
	assert.True(t, released(release), "the end of the ticking streams releases the retry")
}

// The last ticking stream can drop between the read of the decision inputs and
// the decision. The decision then holds on stale inputs, and the channel the
// attempt waits on must already be closed, so it decides again at once
// instead of waiting for the next wake.
func TestRetryRecheckBetweenInputAndDecision(t *testing.T) {
	r, unregister := restartRig(t, testPeriod)
	r.clk.advanceTo(r.down.Add(FastRetryWindow + time.Second))

	woke := r.w.gate.waitChan()
	in := r.w.retryInput(RetrySync, r.down)
	require.True(t, in.ticking, "the streams tick when the inputs are read")
	unregister()
	allow, held := r.w.gate.decide(in)
	require.False(t, allow, "stale inputs hold the attempt")
	require.True(t, held, "stale inputs hold the attempt")
	select {
	case <-woke:
	default:
		t.Fatal("the recheck must close the channel the held attempt waits on")
	}

	went, _ := r.try(t, nil)
	assert.True(t, went, "the next decision sees no ticking stream and lets the attempt go")
}

// A held attempt and the drop of the last ticking streams run at the same
// time. The attempt must go every time.
func TestRetryConcurrentStreamDropReleases(t *testing.T) {
	for i := 0; i < 20; i++ {
		r, unregister := restartRig(t, testPeriod)
		r.clk.advanceTo(r.down.Add(FastRetryWindow + time.Second))

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		done := make(chan error, 1)
		start := make(chan struct{})
		go func() {
			<-start
			_, err := r.w.WaitManagementRetry(ctx, RetrySync, r.down, nil)
			done <- err
		}()
		go func() {
			<-start
			unregister()
		}()
		close(start)
		select {
		case err := <-done:
			require.NoError(t, err, "round %d: the attempt must go", i)
		case <-time.After(time.Second):
			t.Fatalf("round %d: the attempt stayed held after the streams dropped", i)
		}
		cancel()
	}
}

// The attempt of one burst went a few seconds after its wake. The next burst
// comes one period after that wake, less than a period after the attempt, and
// must still let one attempt through.
func TestRetryNextBurstAfterLateAttempt(t *testing.T) {
	r := newRetryRig(t)
	r.down = r.down.Add(-time.Minute)
	r.w.SetDeviceAsleep(true)

	r.clk.advanceTo(tickAt(2))
	r.w.Seen(Signal, beat)
	r.clk.advanceTo(tickAt(2).Add(3500 * time.Millisecond))
	went, _ := r.try(t, nil)
	require.True(t, went, "the attempt inside the wake goes")

	went, release := r.try(t, nil)
	require.False(t, went, "a second attempt in the same wake is held")

	r.clk.advanceTo(tickAt(3))
	r.w.Seen(Signal, beat)
	assert.True(t, released(release), "the next burst lets one attempt through")

	went, _ = r.try(t, nil)
	assert.False(t, went, "only one attempt per wake")
}
