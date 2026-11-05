package keepalive

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

type responder struct {
	ready chan struct{}
	s     *Sender
}

func newResponder() *responder {
	return &responder{ready: make(chan struct{})}
}

func (r *responder) attach(s *Sender) {
	r.s = s
	close(r.ready)
}

func (r *responder) respondLater() {
	r.respondAfter(10 * time.Millisecond)
}

func (r *responder) respondAfter(d time.Duration) {
	go func() {
		<-r.ready
		time.Sleep(d)
		r.s.OnResponse()
	}()
}

func TestSenderRetriesLostRequest(t *testing.T) {
	var attempts atomic.Int32
	responder := newResponder()
	s := newTestSender(t, func([]byte) (int, error) {
		if attempts.Add(1) == 1 {
			return 0, nil
		}
		responder.respondLater()
		return 0, nil
	})
	responder.attach(s)
	defer stopAndWait(s)

	requireNoTimeout(t, s, 500*time.Millisecond)
	require.GreaterOrEqual(t, attempts.Load(), int32(2))
}

func TestSenderTimesOutWithoutResponse(t *testing.T) {
	var attempts atomic.Int32
	s := newTestSender(t, func([]byte) (int, error) {
		attempts.Add(1)
		return 0, nil
	})
	defer stopAndWait(s)

	requireTimeout(t, s, time.Second)
	require.GreaterOrEqual(t, attempts.Load(), int32(3))
}

func TestSenderStopsAfterThreeResends(t *testing.T) {
	var attempts atomic.Int32
	setTestTimings(t)
	retryInterval = 20 * time.Millisecond
	s := NewSender(log.NewEntry(log.New()), func([]byte) (int, error) {
		attempts.Add(1)
		return 0, nil
	})
	defer stopAndWait(s)

	requireTimeout(t, s, time.Second)
	require.Equal(t, int32(1+maxResends), attempts.Load())
}

func TestSenderRetriesFailedWrite(t *testing.T) {
	var attempts atomic.Int32
	responder := newResponder()
	s := newTestSender(t, func([]byte) (int, error) {
		if attempts.Add(1) <= 2 {
			return 0, errors.New("write failed")
		}
		responder.respondLater()
		return 0, nil
	})
	responder.attach(s)
	defer stopAndWait(s)

	requireNoTimeout(t, s, 500*time.Millisecond)
	require.GreaterOrEqual(t, attempts.Load(), int32(3))
}

func TestSenderTimesOutWhenWriteBlocks(t *testing.T) {
	block := make(chan struct{})
	s := newTestSender(t, func([]byte) (int, error) {
		<-block
		return 0, nil
	})
	defer stopAndWait(s)
	defer close(block)

	requireTimeout(t, s, time.Second)
}

func TestSenderResponseWindowStartsAtHandOff(t *testing.T) {
	responder := newResponder()
	s := newTestSender(t, func([]byte) (int, error) {
		time.Sleep(150 * time.Millisecond)
		responder.respondAfter(100 * time.Millisecond)
		return 0, nil
	})
	responder.attach(s)
	defer stopAndWait(s)

	requireNoTimeout(t, s, 700*time.Millisecond)
}

func TestSenderResponseReadBeforeTimeoutHandlingKeepsConnection(t *testing.T) {
	s := newIdleTestSender(t, func([]byte) (int, error) { return 0, nil })
	timeout, retry := newStoppedTimer(), newStoppedTimer()
	startHandedOverProbe(t, s, timeout, retry)

	s.OnResponse()
	time.Sleep(300 * time.Millisecond)

	require.False(t, s.handleTimeout(timeout, retry))
	require.False(t, s.probing)
	requireNoPendingTimeout(t, s)
}

func TestSenderTimeoutWithoutResponseCloses(t *testing.T) {
	s := newIdleTestSender(t, func([]byte) (int, error) { return 0, nil })
	timeout, retry := newStoppedTimer(), newStoppedTimer()
	startHandedOverProbe(t, s, timeout, retry)

	require.True(t, s.handleTimeout(timeout, retry))
	requireTimeout(t, s, time.Second)
}

func TestSenderResponseReadBeforeProbeDoesNotCount(t *testing.T) {
	s := newIdleTestSender(t, func([]byte) (int, error) { return 0, nil })
	timeout, retry := newStoppedTimer(), newStoppedTimer()

	s.OnResponse()
	startHandedOverProbe(t, s, timeout, retry)

	require.True(t, s.handleTimeout(timeout, retry))
	requireTimeout(t, s, time.Second)
}

func TestSenderHandoffRecordedBeforeTimeoutHandlingKeepsConnection(t *testing.T) {
	s := newIdleTestSender(t, func([]byte) (int, error) { return 0, nil })
	timeout, retry := newStoppedTimer(), newStoppedTimer()
	s.startProbe(wallClock(), timeout)
	require.Eventually(t, func() bool { return s.handoffs.Load() == 1 }, time.Second, time.Millisecond)

	require.False(t, s.handleTimeout(timeout, retry))
	require.True(t, s.handedOver)
	require.True(t, s.probing)
	requireNoPendingTimeout(t, s)

	s.handleWriteDone(<-s.writeDone, timeout, retry)
	require.Equal(t, 1, s.attempts)
}

func TestSenderResendSkipsWhenResponseAlreadyRead(t *testing.T) {
	var attempts atomic.Int32
	s := newIdleTestSender(t, func([]byte) (int, error) {
		attempts.Add(1)
		return 0, nil
	})
	timeout, retry := newStoppedTimer(), newStoppedTimer()
	startHandedOverProbe(t, s, timeout, retry)

	s.OnResponse()
	s.resend(timeout, retry)

	require.False(t, s.probing)
	require.Equal(t, int32(1), attempts.Load())
}

func newTestSender(t *testing.T, write func([]byte) (int, error)) *Sender {
	t.Helper()
	setTestTimings(t)
	return NewSender(log.NewEntry(log.New()), write)
}

func newIdleTestSender(t *testing.T, write func([]byte) (int, error)) *Sender {
	t.Helper()
	setTestTimings(t)
	return newSender(log.NewEntry(log.New()), write)
}

func setTestTimings(t *testing.T) {
	t.Helper()
	t.Setenv(envInterval, "1ms")
	t.Setenv(envResponseTimeout, "200ms")
	t.Setenv(envAllowance, "10s")
	previousPoll, previousRetry := pollInterval, retryInterval
	pollInterval = 10 * time.Millisecond
	retryInterval = 50 * time.Millisecond
	t.Cleanup(func() { pollInterval, retryInterval = previousPoll, previousRetry })
}

func startHandedOverProbe(t *testing.T, s *Sender, timeout, retry *time.Timer) {
	t.Helper()
	s.startProbe(wallClock(), timeout)
	select {
	case err := <-s.writeDone:
		s.handleWriteDone(err, timeout, retry)
	case <-time.After(time.Second):
		t.Fatal("request was not handed to the transport")
	}
	require.True(t, s.handedOver)
}

func requireNoPendingTimeout(t *testing.T, s *Sender) {
	t.Helper()
	select {
	case <-s.OnTimeout:
		t.Fatal("unexpected keepalive timeout")
	default:
	}
}

func stopAndWait(s *Sender) {
	s.Stop()
	for range s.OnTimeout {
	}
}

func requireTimeout(t *testing.T, s *Sender, within time.Duration) {
	t.Helper()
	select {
	case _, ok := <-s.OnTimeout:
		require.True(t, ok)
	case <-time.After(within):
		t.Fatal("expected keepalive timeout")
	}
}

func requireNoTimeout(t *testing.T, s *Sender, within time.Duration) {
	t.Helper()
	select {
	case <-s.OnTimeout:
		t.Fatal("unexpected keepalive timeout")
	case <-time.After(within):
	}
}
