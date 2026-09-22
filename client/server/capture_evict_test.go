package server

import (
	"io"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/util/capture"
)

// signalOnWrite delegates to w and closes signal as the first write starts, so
// a test can wait until the capture's writer goroutine is actually inside a
// write that will not return.
type signalOnWrite struct {
	w      io.Writer
	once   sync.Once
	signal chan struct{}
}

func (s *signalOnWrite) Write(p []byte) (int, error) {
	s.once.Do(func() { close(s.signal) })
	return s.w.Write(p)
}

// stalledCapture returns a running capture session whose writer goroutine is
// blocked writing into a pipe nobody reads, plus the cancel that closes the
// pipe's write end (the shape StartCapture installs).
func stalledCapture(t *testing.T) (*capture.Session, func()) {
	t.Helper()

	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pr.Close() })

	writing := make(chan struct{})
	sess, err := capture.NewSession(capture.Options{
		TextOutput: &signalOnWrite{w: pw, signal: writing},
		BufSize:    16,
	})
	require.NoError(t, err)

	sess.Offer([]byte{0x45, 0x00, 0x00, 0x14}, true)

	select {
	case <-writing:
	case <-time.After(5 * time.Second):
		t.Fatal("capture writer never reached the stalled pipe")
	}

	return sess, func() { _ = pw.Close() }
}

// TestClaimCapture_EvictionDoesNotHoldMutex covers the eviction deadlock: the
// evicted session's Stop waits for a writer goroutine that only the pipe close
// can release, so doing that wait under s.mutex wedges every RPC that needs the
// lock. The eviction must close the pipe first and wait outside the lock.
func TestClaimCapture_EvictionDoesNotHoldMutex(t *testing.T) {
	sess, cancel := stalledCapture(t)

	s := &Server{}
	s.activeCapture = sess
	s.activeCaptureCancel = cancel

	claimed := make(chan struct{})
	go func() {
		defer close(claimed)
		// No engine is wired up, so the claim itself fails. The eviction still
		// runs, and that is what must not block or strand the mutex.
		_, _ = s.claimCapture(nil, nil)
	}()

	select {
	case <-claimed:
	case <-time.After(10 * time.Second):
		t.Fatal("claimCapture blocked evicting a stalled capture")
	}

	locked := make(chan struct{})
	go func() {
		s.mutex.Lock()
		s.mutex.Unlock()
		close(locked)
	}()

	select {
	case <-locked:
	case <-time.After(5 * time.Second):
		t.Fatal("s.mutex still held after evicting a stalled capture")
	}

	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("evicted capture session was never stopped")
	}
}

// TestStartBundleCapture_EvictionDoesNotHoldMutex covers the other caller of
// evictActiveCaptureLocked: a debug bundle started while a streaming capture is
// stalled must not wedge the daemon either.
func TestStartBundleCapture_EvictionDoesNotHoldMutex(t *testing.T) {
	sess, cancel := stalledCapture(t)

	s := &Server{}
	s.activeCapture = sess
	s.activeCaptureCancel = cancel

	started := make(chan struct{})
	go func() {
		defer close(started)
		// getCaptureEngineLocked fails without a connected client, which returns
		// success with capture skipped; the eviction has already happened.
		_, _ = s.StartBundleCapture(t.Context(), nil)
	}()

	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("StartBundleCapture blocked evicting a stalled capture")
	}

	select {
	case <-sess.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("evicted capture session was never stopped")
	}
}
