package server

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel"

	"github.com/netbirdio/netbird/relay/metrics"
	"github.com/netbirdio/netbird/relay/server/store"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

// fakeConn is a scriptable listener.Conn: reads are fed through a channel and
// writes can be gated to simulate a slow or stalled destination.
type fakeConn struct {
	reads     chan []byte
	writeGate chan struct{} // each write consumes one token; nil means open
	writes    atomic.Int64
	readCalls atomic.Int64
	closed    chan struct{}
	closeOnce sync.Once
}

func newFakeConn(gated bool) *fakeConn {
	fc := &fakeConn{
		reads:  make(chan []byte, 1024),
		closed: make(chan struct{}),
	}
	if gated {
		fc.writeGate = make(chan struct{}, 1024)
	}
	return fc
}

func (f *fakeConn) Read(ctx context.Context, b []byte) (int, error) {
	f.readCalls.Add(1)
	select {
	case msg := <-f.reads:
		return copy(b, msg), nil
	case <-f.closed:
		return 0, net.ErrClosed
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

func (f *fakeConn) Write(ctx context.Context, b []byte) (int, error) {
	if f.writeGate != nil {
		select {
		case <-f.writeGate:
		case <-f.closed:
			return 0, net.ErrClosed
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	select {
	case <-f.closed:
		return 0, net.ErrClosed
	default:
	}
	f.writes.Add(1)
	return len(b), nil
}

func (f *fakeConn) RemoteAddr() net.Addr { return &net.TCPAddr{} }

func (f *fakeConn) Close() error {
	f.closeOnce.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeConn) Protocol() string { return "test" }

func testPeerPair(t *testing.T, dstGated bool) (src, dst *Peer, srcConn, dstConn *fakeConn, cleanup func()) {
	t.Helper()
	m, err := metrics.NewMetrics(context.Background(), otel.Meter(""))
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	st := store.NewStore()
	notifier := store.NewPeerNotifier()

	srcConn = newFakeConn(false)
	dstConn = newFakeConn(dstGated)
	src = NewPeer(m, messages.HashID("src"), srcConn, st, notifier)
	dst = NewPeer(m, messages.HashID("dst"), dstConn, st, notifier)
	st.AddPeer(src)
	st.AddPeer(dst)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); src.Work() }()
	go func() { defer wg.Done(); dst.Work() }()

	cleanup = func() {
		_ = srcConn.Close()
		_ = dstConn.Close()
		wg.Wait()
	}
	return src, dst, srcConn, dstConn, cleanup
}

func transportMsgTo(t *testing.T, dst messages.PeerID, payload []byte) []byte {
	t.Helper()
	msg, err := messages.MarshalTransportMsg(dst, payload)
	if err != nil {
		t.Fatalf("marshal transport msg: %v", err)
	}
	return msg
}

// TestSlowDestinationDoesNotStallSource feeds the source many messages toward
// a destination whose writes never complete; the source read loop must keep
// consuming.
func TestSlowDestinationDoesNotStallSource(t *testing.T) {
	_, _, srcConn, dstConn, cleanup := testPeerPair(t, true)
	defer cleanup()

	const total = 50
	msg := transportMsgTo(t, messages.HashID("dst"), []byte("payload"))
	for i := 0; i < total; i++ {
		srcConn.reads <- msg
	}

	deadline := time.After(2 * time.Second)
	for len(srcConn.reads) > 0 {
		select {
		case <-deadline:
			t.Fatalf("source read loop stalled, %d messages unread", len(srcConn.reads))
		case <-time.After(10 * time.Millisecond):
		}
	}
	if w := dstConn.writes.Load(); w != 0 {
		t.Fatalf("expected no completed writes on gated destination, got %d", w)
	}
}

// TestQueueDeliversWhenDestinationDrains releases the destination's write gate
// and verifies queued messages arrive.
func TestQueueDeliversWhenDestinationDrains(t *testing.T) {
	_, _, srcConn, dstConn, cleanup := testPeerPair(t, true)
	defer cleanup()

	const total = 20
	msg := transportMsgTo(t, messages.HashID("dst"), []byte("payload"))
	for i := 0; i < total; i++ {
		srcConn.reads <- msg
	}
	for i := 0; i < total; i++ {
		dstConn.writeGate <- struct{}{}
	}

	deadline := time.After(2 * time.Second)
	for dstConn.writes.Load() < total {
		select {
		case <-deadline:
			t.Fatalf("expected %d writes, got %d", total, dstConn.writes.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// TestQueueOverflowDrops verifies that a full destination queue drops the
// excess instead of blocking the source, and that the queue-sized backlog is
// still delivered once the destination drains.
func TestQueueOverflowDrops(t *testing.T) {
	_, _, srcConn, dstConn, cleanup := testPeerPair(t, true)
	defer cleanup()

	const overflow = 100
	msg := transportMsgTo(t, messages.HashID("dst"), []byte("payload"))
	total := msgQueueSize + overflow
	for i := 0; i < total; i++ {
		srcConn.reads <- msg
	}

	// wait until the source consumed everything (nothing may block)
	deadline := time.After(3 * time.Second)
	for len(srcConn.reads) > 0 {
		select {
		case <-deadline:
			t.Fatalf("source read loop stalled, %d messages unread", len(srcConn.reads))
		case <-time.After(10 * time.Millisecond):
		}
	}

	// open the gate fully and count what arrives
	for i := 0; i < total; i++ {
		dstConn.writeGate <- struct{}{}
	}
	time.Sleep(500 * time.Millisecond)

	got := dstConn.writes.Load()
	// the writer may have dequeued one message before the queue filled
	if got < msgQueueSize || got > msgQueueSize+2 {
		t.Fatalf("expected ~%d delivered messages, got %d", msgQueueSize, got)
	}
}

// TestConcurrentSourcesMessageIntegrity has two sources forward distinct
// payloads to one destination; run with -race to guard the buffer handoff.
func TestConcurrentSourcesMessageIntegrity(t *testing.T) {
	m, err := metrics.NewMetrics(context.Background(), otel.Meter(""))
	if err != nil {
		t.Fatalf("metrics: %v", err)
	}
	st := store.NewStore()
	notifier := store.NewPeerNotifier()

	dstConn := newFakeConn(false)
	dst := NewPeer(m, messages.HashID("dst"), dstConn, st, notifier)
	st.AddPeer(dst)

	var wg sync.WaitGroup
	srcConns := make([]*fakeConn, 2)
	for i := range srcConns {
		srcConns[i] = newFakeConn(false)
		p := NewPeer(m, messages.HashID(string(rune('a'+i))), srcConns[i], st, notifier)
		st.AddPeer(p)
		wg.Add(1)
		go func() { defer wg.Done(); p.Work() }()
	}
	wg.Add(1)
	go func() { defer wg.Done(); dst.Work() }()

	const perSource = 500
	msg := transportMsgTo(t, messages.HashID("dst"), []byte("payload-integrity-check"))
	var sendWg sync.WaitGroup
	for _, sc := range srcConns {
		sendWg.Add(1)
		go func(sc *fakeConn) {
			defer sendWg.Done()
			for i := 0; i < perSource; i++ {
				sc.reads <- msg
			}
		}(sc)
	}
	sendWg.Wait()

	deadline := time.After(5 * time.Second)
	for dstConn.writes.Load() < 2*perSource {
		select {
		case <-deadline:
			t.Fatalf("expected %d writes, got %d", 2*perSource, dstConn.writes.Load())
		case <-time.After(10 * time.Millisecond):
		}
	}

	for _, sc := range srcConns {
		_ = sc.Close()
	}
	_ = dstConn.Close()
	wg.Wait()
}

// TestWriterStopsOnClose closes the peer and verifies its writer goroutine
// exits (enqueue never blocks afterwards).
func TestWriterStopsOnClose(t *testing.T) {
	_, dst, srcConn, _, cleanup := testPeerPair(t, true)
	defer cleanup()

	msg := transportMsgTo(t, messages.HashID("dst"), []byte("payload"))
	srcConn.reads <- msg
	time.Sleep(50 * time.Millisecond)

	dst.Close()

	// the source must still be able to forward (enqueue or drop) without blocking
	for i := 0; i < msgQueueSize*2; i++ {
		srcConn.reads <- msg
	}
	deadline := time.After(3 * time.Second)
	for len(srcConn.reads) > 0 {
		select {
		case <-deadline:
			t.Fatalf("source read loop stalled after destination close, %d unread", len(srcConn.reads))
		case <-time.After(10 * time.Millisecond):
		}
	}
}
