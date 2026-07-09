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
