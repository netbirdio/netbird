package client

import (
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

func newTestContainer(t *testing.T, reliable bool) (*connContainer, *Client) {
	t.Helper()
	c := &Client{
		log:               log.WithField("relay", "test"),
		reliableTransport: reliable,
		bufPool: &sync.Pool{
			New: func() any {
				buf := make([]byte, bufferSize)
				return &buf
			},
		},
		conns: make(map[messages.PeerID]*connContainer),
	}
	cc := newConnContainer(c.log, c, messages.HashID("test-peer"), nil)
	return cc, c
}

func testMsg(c *Client) Msg {
	bufPtr := c.bufPool.Get().(*[]byte)
	return Msg{
		bufPool: c.bufPool,
		bufPtr:  bufPtr,
		Payload: (*bufPtr)[:16],
	}
}

func fillChannel(cc *connContainer, c *Client) {
	for i := 0; i < connChannelSize; i++ {
		cc.writeMsg(testMsg(c))
	}
}

func TestWriteMsgFastPathNoDrop(t *testing.T) {
	cc, c := newTestContainer(t, true)
	defer cc.close()

	const total = connChannelSize * 5
	received := make(chan struct{})
	go func() {
		buf := make([]byte, bufferSize)
		for i := 0; i < total; i++ {
			if _, err := cc.conn.Read(buf); err != nil {
				return
			}
		}
		close(received)
	}()

	for i := 0; i < total; i++ {
		cc.writeMsg(testMsg(c))
	}

	select {
	case <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("receiver did not get all messages")
	}
	if d := c.InboundMsgDrops(); d != 0 {
		t.Fatalf("expected 0 drops, got %d", d)
	}
}

func TestWriteMsgBlocksThenDropsReliable(t *testing.T) {
	cc, c := newTestContainer(t, true)
	defer cc.close()

	fillChannel(cc, c)

	start := time.Now()
	cc.writeMsg(testMsg(c))
	elapsed := time.Since(start)

	if elapsed < msgChanSendTimeout/2 || elapsed > 3*msgChanSendTimeout {
		t.Fatalf("expected ~%v bounded block, got %v", msgChanSendTimeout, elapsed)
	}
	if d := c.InboundMsgDrops(); d != 1 {
		t.Fatalf("expected 1 drop, got %d", d)
	}

	// cooldown: the next overflow drops immediately
	start = time.Now()
	cc.writeMsg(testMsg(c))
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("expected immediate drop during cooldown, took %v", elapsed)
	}
	if d := c.InboundMsgDrops(); d != 2 {
		t.Fatalf("expected 2 drops, got %d", d)
	}
}

func TestWriteMsgBlockedSenderReleasedByDrain(t *testing.T) {
	cc, c := newTestContainer(t, true)
	defer cc.close()

	fillChannel(cc, c)

	done := make(chan struct{})
	go func() {
		cc.writeMsg(testMsg(c))
		close(done)
	}()

	time.Sleep(100 * time.Millisecond)
	buf := make([]byte, bufferSize)
	if _, err := cc.conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}

	select {
	case <-done:
	case <-time.After(msgChanSendTimeout / 2):
		t.Fatal("sender was not released by the drain")
	}
	if d := c.InboundMsgDrops(); d != 0 {
		t.Fatalf("expected 0 drops, got %d", d)
	}
}

func TestWriteMsgImmediateDropDatagram(t *testing.T) {
	cc, c := newTestContainer(t, false)
	defer cc.close()

	fillChannel(cc, c)

	start := time.Now()
	cc.writeMsg(testMsg(c))
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("expected immediate drop on datagram transport, took %v", elapsed)
	}
	if d := c.InboundMsgDrops(); d != 1 {
		t.Fatalf("expected 1 drop, got %d", d)
	}
}

// TestReadBatchDrainsInOrder verifies Conn.ReadBatch returns queued packets in
// FIFO order, copies each payload out, frees every Msg exactly once (no pool
// double-free — run with -race), and reports no drops.
func TestReadBatchDrainsInOrder(t *testing.T) {
	cc, c := newTestContainer(t, true)
	defer cc.close()

	const total = 10
	for i := 0; i < total; i++ {
		bufPtr := c.bufPool.Get().(*[]byte)
		(*bufPtr)[0] = byte(i)
		cc.writeMsg(Msg{bufPool: c.bufPool, bufPtr: bufPtr, Payload: (*bufPtr)[:16]})
	}

	const batch = 4
	bufs := make([][]byte, batch)
	sizes := make([]int, batch)
	for i := range bufs {
		bufs[i] = make([]byte, bufferSize)
	}

	got := 0
	for got < total {
		n, err := cc.conn.ReadBatch(bufs, sizes)
		if err != nil {
			t.Fatalf("ReadBatch: %v", err)
		}
		if n <= 0 || n > batch {
			t.Fatalf("ReadBatch returned n=%d, want 1..%d", n, batch)
		}
		for i := 0; i < n; i++ {
			if sizes[i] != 16 {
				t.Fatalf("sizes[%d]=%d, want 16", i, sizes[i])
			}
			if bufs[i][0] != byte(got) {
				t.Fatalf("out of order: got marker %d, want %d", bufs[i][0], got)
			}
			got++
		}
	}
	if d := c.InboundMsgDrops(); d != 0 {
		t.Fatalf("expected 0 drops, got %d", d)
	}
}

// TestReadBatchDrainsOnlyAvailable verifies ReadBatch blocks for the first
// packet then returns whatever is already queued without waiting for the batch
// to fill.
func TestReadBatchDrainsOnlyAvailable(t *testing.T) {
	cc, c := newTestContainer(t, true)
	defer cc.close()

	const queued = 3
	for i := 0; i < queued; i++ {
		cc.writeMsg(testMsg(c))
	}

	bufs := make([][]byte, 8)
	sizes := make([]int, 8)
	for i := range bufs {
		bufs[i] = make([]byte, bufferSize)
	}

	n, err := cc.conn.ReadBatch(bufs, sizes)
	if err != nil {
		t.Fatalf("ReadBatch: %v", err)
	}
	if n != queued {
		t.Fatalf("ReadBatch returned n=%d, want %d (only what was queued)", n, queued)
	}
}

// TestCloseUnblocksPendingWriters guards against a send on the closed messages
// channel when close() races blocked writeMsg calls. Run with -race.
func TestCloseUnblocksPendingWriters(t *testing.T) {
	for i := 0; i < 200; i++ {
		cc, c := newTestContainer(t, true)
		fillChannel(cc, c)

		var wg sync.WaitGroup
		for s := 0; s < 4; s++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cc.writeMsg(testMsg(c))
			}()
		}

		closed := make(chan struct{})
		go func() {
			cc.close()
			close(closed)
		}()

		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("close did not return")
		}
		wg.Wait()

		// the reader must observe EOF via the closed channel
		buf := make([]byte, bufferSize)
		if _, err := cc.conn.Read(buf); err == nil {
			// drained a leftover message; the channel still must be closed
			for {
				if _, err := cc.conn.Read(buf); err != nil {
					break
				}
			}
		}
	}
}
