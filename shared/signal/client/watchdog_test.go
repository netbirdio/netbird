package client

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/grpc"

	sigProto "github.com/netbirdio/netbird/shared/signal/proto"
	"github.com/netbirdio/netbird/signal/server"
)

func startTestSignalServer(t *testing.T) string {
	t.Helper()

	srv, err := server.NewServer(context.Background(), otel.Meter(""))
	require.NoError(t, err)

	return serveTestSignalExchange(t, srv)
}

func serveTestSignalExchange(t *testing.T, impl sigProto.SignalExchangeServer) string {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	s := grpc.NewServer()
	sigProto.RegisterSignalExchangeServer(s, impl)

	go func() {
		_ = s.Serve(lis)
	}()
	t.Cleanup(s.Stop)

	return lis.Addr().String()
}

// TestReceiveProbeRoundTrips verifies that the watchdog's self-addressed heartbeat
// is routed back to the same client through the signal server. This round-trip is
// what lets the watchdog confirm the receive direction is still delivering.
func TestReceiveProbeRoundTrips(t *testing.T) {
	addr := startTestSignalServer(t)

	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	client, err := NewClient(ctx, addr, key, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	received := make(chan struct{}, 1)
	go func() {
		_ = client.Receive(ctx, func(msg *sigProto.Message) error {
			if msg.GetBody().GetType() == sigProto.Body_HEARTBEAT && msg.GetKey() == key.PublicKey().String() {
				select {
				case received <- struct{}{}:
				default:
				}
			}
			return nil
		})
	}()

	streamReady := make(chan struct{})
	go func() {
		client.WaitStreamConnected(ctx)
		close(streamReady)
	}()
	select {
	case <-streamReady:
	case <-time.After(5 * time.Second):
		t.Fatal("signal stream did not connect within timeout")
	}

	require.NoError(t, client.sendReceiveProbe(ctx))

	select {
	case <-received:
	case <-time.After(3 * time.Second):
		t.Fatal("self-addressed heartbeat did not round-trip back through the signal server")
	}
}

// TestReceiveAliveTreatsHandoffBlockAsLiveness reproduces the false positive
// where a busy decryption worker parks the receive loop on the worker handoff,
// so Recv (and markReceived) stops firing even though the stream is healthy.
// With no frame since the last check but the loop blocked on handoff, the
// watchdog must consider the stream alive rather than tear it down (reconnecting
// feeds the same worker and would not help).
func TestReceivedSinceTreatsHandoffBlockAsLiveness(t *testing.T) {
	c := &GrpcClient{}
	c.markReceived()
	_, last := c.receivedSince(0)

	// No frame since the last check and the loop not blocked on handoff: silent.
	alive, _ := c.receivedSince(last)
	require.False(t, alive, "silent stream with the receive loop idle must count as a silent check")

	// No frame, but the loop is parked handing a message to a busy worker:
	// self-inflicted backpressure, not a dead stream.
	c.receiveHandoffBlocked.Store(true)
	alive, _ = c.receivedSince(last)
	require.True(t, alive, "a receive loop blocked on worker handoff must keep the stream alive")

	// Handoff drained, a frame just arrived: alive via the receive path.
	c.receiveHandoffBlocked.Store(false)
	time.Sleep(time.Millisecond)
	c.markReceived()
	alive, _ = c.receivedSince(last)
	require.True(t, alive, "a freshly received frame must keep the stream alive")
}

// fakeRecvStream feeds the receive loop frames from a channel and reports EOF
// once the channel is closed. Only Recv is exercised by the loop.
type fakeRecvStream struct {
	sigProto.SignalExchange_ConnectStreamClient
	frames chan *sigProto.EncryptedMessage
}

func (s *fakeRecvStream) Recv() (*sigProto.EncryptedMessage, error) {
	msg, ok := <-s.frames
	if !ok {
		return nil, io.EOF
	}
	return msg, nil
}

// TestReceiveLoopRefreshesLivenessAfterBlockedHandoff drives the real receive
// loop into a handoff that blocks past the inactivity threshold, then checks the
// window after the handoff drains but before the next Recv. The loop must have
// refreshed the timestamp on unblocking, otherwise that window reads the stale
// pre-handoff timestamp as a dead stream and the watchdog tears down a healthy
// connection.
func TestReceiveLoopRefreshesLivenessAfterBlockedHandoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := &GrpcClient{ctx: ctx}

	handling := make(chan struct{}, 8)
	gate := make(chan struct{})
	decrypt := func(*sigProto.EncryptedMessage) (*sigProto.Message, error) { return &sigProto.Message{}, nil }
	handler := func(*sigProto.Message) error {
		handling <- struct{}{}
		<-gate
		return nil
	}
	c.decryptionWorker = NewWorker(decrypt, handler)
	workerCtx, workerCancel := context.WithCancel(context.Background())
	go c.decryptionWorker.Work(workerCtx)
	t.Cleanup(workerCancel)

	frames := make(chan *sigProto.EncryptedMessage)
	t.Cleanup(func() { close(frames) })
	go func() { _ = c.receive(&fakeRecvStream{frames: frames}) }()

	// First frame: the worker drains it and parks in the blocking handler.
	frames <- &sigProto.EncryptedMessage{}
	<-handling
	// Second frame fills the worker's single-slot pool.
	frames <- &sigProto.EncryptedMessage{}
	// Third frame: the pool is full, so the loop parks on the handoff.
	frames <- &sigProto.EncryptedMessage{}

	require.Eventually(t, c.receiveHandoffBlocked.Load, time.Second, time.Millisecond,
		"receive loop should park on the worker handoff")

	// A check taken while the loop is parked on the handoff.
	alive, last := c.receivedSince(c.lastReceived.Load())
	require.True(t, alive, "a loop parked on the handoff must stay alive")

	// Drain the worker so the handoff returns and the loop resumes reading.
	close(gate)

	// Once the handoff clears, the loop is parked on the next Recv with no frame
	// pending. The stream must still read as alive in that window.
	require.Eventually(t, func() bool { return !c.receiveHandoffBlocked.Load() }, time.Second, time.Millisecond,
		"handoff should drain once the worker is released")
	alive, _ = c.receivedSince(last)
	require.True(t, alive,
		"the loop must refresh liveness when the handoff drains, before the next Recv")
}

// fastWatchdogClient returns a client with watchdog ticks short enough for a unit test.
func fastWatchdogClient() *GrpcClient {
	return &GrpcClient{watchdog: watchdogTimings{interval: 2 * time.Millisecond}}
}

// TestWatchdogRetriesUnsentProbe covers a probe that fails to leave the client,
// for example because the Send path is rejecting calls. That says nothing about
// the receive direction, so the watchdog must retry the probe instead of tearing
// down a stream it never tested.
func TestWatchdogRetriesUnsentProbe(t *testing.T) {
	c := fastWatchdogClient()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var probes atomic.Int32
	probe := func(context.Context) error {
		probes.Add(1)
		return errors.New("send path rejected the probe")
	}
	var tornDown atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.watchReceiveStream(ctx, func() { tornDown.Store(true) }, probe, false)
	}()

	// Ten attempts span many teardown windows.
	require.Eventually(t, func() bool { return probes.Load() >= 10 }, 5*time.Second, time.Millisecond,
		"the watchdog must keep retrying a probe that could not be sent")
	assert.False(t, tornDown.Load(), "a probe that never left must not tear down the stream")
	cancel()
	<-done
}

// TestWatchdogTearsDownWhenSentProbeIsLost keeps the existing guarantee: a probe
// that left the client but never came back on the stream ends the stream.
func TestWatchdogTearsDownWhenSentProbeIsLost(t *testing.T) {
	c := fastWatchdogClient()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	tornDown := make(chan struct{})
	go c.watchReceiveStream(ctx, func() { close(tornDown) }, func(context.Context) error { return nil }, false)

	select {
	case <-tornDown:
	case <-time.After(5 * time.Second):
		t.Fatal("a lost probe must tear down the stream")
	}
	assert.True(t, c.receiveStalled.Load(), "the stall must be reported to IsHealthy")
}

// TestWatchdogTearsDownWhenProbeWriteBlocks covers a probe write held by flow
// control because Signal stopped reading the connection. Only cancelling the
// stream releases that write, and only the watchdog cancels it: a watchdog that
// waits for the write never tears the silent stream down.
func TestWatchdogTearsDownWhenProbeWriteBlocks(t *testing.T) {
	c := fastWatchdogClient()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	released := make(chan struct{})
	tornDown := make(chan struct{})
	go c.watchReceiveStream(ctx, func() {
		close(tornDown)
		close(released)
	}, func(context.Context) error {
		<-released
		return errors.New("stream cancelled")
	}, false)

	select {
	case <-tornDown:
	case <-time.After(5 * time.Second):
		t.Fatal("a probe write that never completes must still tear down the stream")
	}
	assert.True(t, c.receiveStalled.Load(), "the stall must be reported to IsHealthy")
}

// TestWatchdogsStartedTogetherProbeApart reproduces a fleet that reconnected in
// the same instant: without jitter every watchdog checks on the same tick and
// probes in step. The first probes must spread across the interval.
func TestWatchdogsStartedTogetherProbeApart(t *testing.T) {
	const watchdogs = 20
	interval := 400 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	firstProbe := make(chan time.Time, watchdogs)
	for i := 0; i < watchdogs; i++ {
		c := &GrpcClient{watchdog: watchdogTimings{interval: interval}}
		var once atomic.Bool
		go c.watchReceiveStream(ctx, func() {}, func(context.Context) error {
			if once.CompareAndSwap(false, true) {
				firstProbe <- time.Now()
			}
			return nil
		}, false)
	}

	var earliest, latest time.Time
	for i := 0; i < watchdogs; i++ {
		select {
		case at := <-firstProbe:
			if earliest.IsZero() || at.Before(earliest) {
				earliest = at
			}
			if at.After(latest) {
				latest = at
			}
		case <-time.After(5 * time.Second):
			t.Fatal("a watchdog never probed")
		}
	}
	assert.Greater(t, latest.Sub(earliest), interval/4,
		"watchdogs started together must not probe in step")
}

// TestWatchdogTickIsJittered checks that every check after the first is drawn
// within the jitter window, so watchdogs that started together drift apart.
func TestWatchdogTickIsJittered(t *testing.T) {
	timings := watchdogTimings{}.withDefaults()
	seen := map[time.Duration]bool{}
	for i := 0; i < 50; i++ {
		next := timings.next()
		require.GreaterOrEqual(t, next, receiveWatchdogInterval, "tick below the interval")
		require.Less(t, next, receiveWatchdogInterval*13/10, "tick past the jitter window")
		seen[next] = true
	}
	assert.Greater(t, len(seen), 1, "ticks must not share one length")
}

// TestWatchdogWaitsForTheRegistrationProbe starts the watchdog with the
// registration probe still unanswered: a silent stream must be torn down without
// another probe being written behind the first one.
func TestWatchdogWaitsForTheRegistrationProbe(t *testing.T) {
	c := fastWatchdogClient()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var probes atomic.Int32
	tornDown := make(chan struct{})
	go c.watchReceiveStream(ctx, func() { close(tornDown) }, func(context.Context) error {
		probes.Add(1)
		return nil
	}, true)

	select {
	case <-tornDown:
	case <-time.After(5 * time.Second):
		t.Fatal("an unanswered registration probe must tear down a silent stream")
	}
	assert.Zero(t, probes.Load(), "the watchdog must not probe while the registration probe is pending")
}

// TestWatchdogMessagesKeepTheStreamWithoutProbes feeds the stream a message on
// every check: offers and answers prove it alive, so no probe is needed.
func TestWatchdogMessagesKeepTheStreamWithoutProbes(t *testing.T) {
	c := fastWatchdogClient()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	var probes atomic.Int32
	var tornDown atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.watchReceiveStream(ctx, func() { tornDown.Store(true) }, func(context.Context) error {
			probes.Add(1)
			return nil
		}, true)
	}()

	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		c.markReceived()
		time.Sleep(100 * time.Microsecond)
	}
	cancel()
	<-done
	assert.False(t, tornDown.Load(), "a stream delivering messages must not be torn down")
	assert.Zero(t, probes.Load(), "a stream delivering messages must not be probed")
}

// TestRepeatedWatchdogTeardown decides when the reconnect backoff keeps growing:
// only a watchdog stall that follows another one within the window.
func TestRepeatedWatchdogTeardown(t *testing.T) {
	c := &GrpcClient{}
	now := time.Now()

	assert.False(t, c.repeatedWatchdogTeardown(now), "a stream that ended for another reason resets the backoff")

	c.receiveStalled.Store(true)
	assert.False(t, c.repeatedWatchdogTeardown(now), "the first stall reconnects at once")
	assert.True(t, c.repeatedWatchdogTeardown(now.Add(time.Minute)), "a second stall soon after must back off")
	assert.False(t, c.repeatedWatchdogTeardown(now.Add(time.Minute+watchdogTeardownBackoffWindow)),
		"a stall long after the previous one reconnects at once")
}
