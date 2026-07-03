package tcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIsClosedListenerErr_NetErrClosed verifies the stdlib path: a
// closed *net.Listener returns net.ErrClosed wrapped in *net.OpError,
// and IsClosedListenerErr must unwrap it.
func TestIsClosedListenerErr_NetErrClosed(t *testing.T) {
	wrapped := &net.OpError{Op: "accept", Net: "tcp", Err: net.ErrClosed}
	assert.True(t, IsClosedListenerErr(wrapped),
		"net.OpError wrapping net.ErrClosed must be recognised as closed")
}

// TestIsClosedListenerErr_GVisorInvalidEndpoint is the load-bearing
// regression guard. A gVisor netstack listener whose endpoint has been
// destroyed returns this exact text. Without recognising it the accept
// loop spins forever and burns a CPU core.
func TestIsClosedListenerErr_GVisorInvalidEndpoint(t *testing.T) {
	err := fmt.Errorf("accept tcp 10.10.1.254:80: endpoint is in invalid state")
	assert.True(t, IsClosedListenerErr(err),
		"gVisor 'endpoint is in invalid state' must be recognised as closed")
}

// TestIsClosedListenerErr_OtherError confirms we don't over-match —
// transient errors must keep returning false so the backoff path runs.
func TestIsClosedListenerErr_OtherError(t *testing.T) {
	cases := []error{
		errors.New("temporary failure"),
		errors.New("accept tcp 10.10.1.254:80: too many open files"),
		nil,
	}
	for _, c := range cases {
		assert.False(t, IsClosedListenerErr(c),
			"unexpected match on %v — must not be treated as closed", c)
	}
}

// TestAcceptBackoff_ProgressionAndCap asserts the doubling schedule:
// 5ms, 10ms, 20ms, 40ms, ... capped at 1s. The test runs against a
// real timer but uses tight bounds so a slow CI machine still passes.
func TestAcceptBackoff_ProgressionAndCap(t *testing.T) {
	var b AcceptBackoff
	expected := []time.Duration{
		5 * time.Millisecond,
		10 * time.Millisecond,
		20 * time.Millisecond,
		40 * time.Millisecond,
	}
	for i, want := range expected {
		start := time.Now()
		ok := b.Backoff(context.Background())
		elapsed := time.Since(start)
		require.True(t, ok, "Backoff %d must complete; ctx is alive", i)
		assert.GreaterOrEqual(t, elapsed, want,
			"backoff %d (%v) must wait at least the configured delay", i, want)
		assert.Less(t, elapsed, want*4,
			"backoff %d (%v) must not overshoot by more than 4x — caps misbehaving", i, want)
	}

	// Burn enough rounds to reach the cap, then assert subsequent
	// rounds stay at exactly maxAcceptDelay (1s) — the timer should
	// never exceed it.
	for range 6 {
		b.Backoff(context.Background())
	}
	assert.Equal(t, maxAcceptDelay, b.delay,
		"after enough doublings the delay must clamp to maxAcceptDelay")
}

// TestAcceptBackoff_Reset confirms that a successful Accept resets the
// schedule — a busy-then-quiet listener mustn't stay on a 1s timer
// after recovery.
func TestAcceptBackoff_Reset(t *testing.T) {
	var b AcceptBackoff
	for range 5 {
		b.Backoff(context.Background())
	}
	require.NotEqual(t, time.Duration(0), b.delay, "precondition: delay must have accumulated")

	b.Reset()
	assert.Equal(t, time.Duration(0), b.delay, "Reset must zero the delay")

	start := time.Now()
	ok := b.Backoff(context.Background())
	elapsed := time.Since(start)
	require.True(t, ok, "Backoff after Reset must complete")
	assert.GreaterOrEqual(t, elapsed, minAcceptDelay,
		"after Reset the next backoff must restart at minAcceptDelay")
	assert.Less(t, elapsed, 50*time.Millisecond,
		"after Reset the next backoff must NOT carry over the prior delay")
}

// TestAcceptBackoff_CancelDuringWait proves the loop exits promptly
// when ctx fires mid-wait. Without this, a tear-down would still take
// up to 1 second per orphaned listener.
func TestAcceptBackoff_CancelDuringWait(t *testing.T) {
	var b AcceptBackoff
	// Drive the backoff up so the next call will wait ~1s — long
	// enough that we can detect early cancellation.
	for range 10 {
		b.Backoff(context.Background())
	}
	require.Equal(t, maxAcceptDelay, b.delay)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	ok := b.Backoff(ctx)
	elapsed := time.Since(start)
	assert.False(t, ok, "Backoff must return false when ctx is cancelled mid-wait")
	assert.Less(t, elapsed, 200*time.Millisecond,
		"cancellation must short-circuit the timer; took %v", elapsed)
}

// TestAcceptBackoff_CancelBeforeCall — when ctx is already done the
// loop exits without sleeping at all.
func TestAcceptBackoff_CancelBeforeCall(t *testing.T) {
	var b AcceptBackoff
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	ok := b.Backoff(ctx)
	elapsed := time.Since(start)
	assert.False(t, ok, "Backoff must return false when ctx is already cancelled")
	assert.Less(t, elapsed, 50*time.Millisecond,
		"already-cancelled ctx must return immediately; took %v", elapsed)
}
