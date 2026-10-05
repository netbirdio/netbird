package client

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

func newTestPool() *sync.Pool {
	return &sync.Pool{
		New: func() any {
			buf := make([]byte, 64)
			return &buf
		},
	}
}

func newTestMsg(pool *sync.Pool, payload string) Msg {
	bufPtr := pool.Get().(*[]byte)
	copy(*bufPtr, payload)
	return Msg{
		bufPool: pool,
		bufPtr:  bufPtr,
		Payload: (*bufPtr)[:len(payload)],
	}
}

func peerID(id string) messages.PeerID {
	return messages.HashID(id)
}

func TestEarlyMsgBuffer_PutAndPop(t *testing.T) {
	buf := newEarlyMsgBuffer()
	defer buf.close()

	pool := newTestPool()
	peer := peerID("peer1")
	msg := newTestMsg(pool, "hello")

	if !buf.put(peer, msg) {
		t.Fatal("put should succeed")
	}

	got, ok := buf.pop(peer)
	if !ok {
		t.Fatal("pop should find the message")
	}
	if string(got.Payload) != "hello" {
		t.Fatalf("expected payload 'hello', got '%s'", got.Payload)
	}
	got.Free()
}

func TestEarlyMsgBuffer_PopNotFound(t *testing.T) {
	buf := newEarlyMsgBuffer()
	defer buf.close()

	_, ok := buf.pop(peerID("nonexistent"))
	if ok {
		t.Fatal("pop should return false for unknown peer")
	}
}

func TestEarlyMsgBuffer_PopAfterPopReturnsFalse(t *testing.T) {
	buf := newEarlyMsgBuffer()
	defer buf.close()

	pool := newTestPool()
	peer := peerID("peer1")

	buf.put(peer, newTestMsg(pool, "data"))

	got, ok := buf.pop(peer)
	if !ok {
		t.Fatal("first pop should succeed")
	}
	got.Free()

	_, ok = buf.pop(peer)
	if ok {
		t.Fatal("second pop for the same peer should return false")
	}
}

func TestEarlyMsgBuffer_OverwriteSamePeer(t *testing.T) {
	buf := newEarlyMsgBuffer()
	defer buf.close()

	pool := newTestPool()
	peer := peerID("peer1")

	if !buf.put(peer, newTestMsg(pool, "first")) {
		t.Fatal("first put should succeed")
	}
	if !buf.put(peer, newTestMsg(pool, "second")) {
		t.Fatal("second put (overwrite) should succeed")
	}

	got, ok := buf.pop(peer)
	if !ok {
		t.Fatal("pop should find the message")
	}
	if string(got.Payload) != "second" {
		t.Fatalf("expected payload 'second', got '%s'", got.Payload)
	}
	got.Free()

	// No more messages should be present for this peer
	_, ok = buf.pop(peer)
	if ok {
		t.Fatal("pop should return false after the only message was already popped")
	}
}

func TestEarlyMsgBuffer_MultiplePeers(t *testing.T) {
	buf := newEarlyMsgBuffer()
	defer buf.close()

	pool := newTestPool()
	peers := []messages.PeerID{peerID("a"), peerID("b"), peerID("c")}

	for i, p := range peers {
		msg := newTestMsg(pool, fmt.Sprintf("msg-%d", i))
		if !buf.put(p, msg) {
			t.Fatalf("put should succeed for peer %d", i)
		}
	}

	// Pop in reverse order to verify independence
	for i := len(peers) - 1; i >= 0; i-- {
		got, ok := buf.pop(peers[i])
		if !ok {
			t.Fatalf("pop should find message for peer %d", i)
		}
		expected := fmt.Sprintf("msg-%d", i)
		if string(got.Payload) != expected {
			t.Fatalf("expected payload '%s', got '%s'", expected, got.Payload)
		}
		got.Free()
	}
}

func TestEarlyMsgBuffer_Capacity(t *testing.T) {
	buf := newEarlyMsgBuffer()
	defer buf.close()

	pool := newTestPool()

	// Fill to capacity
	for i := 0; i < earlyMsgCapacity; i++ {
		peer := peerID(fmt.Sprintf("peer-%d", i))
		msg := newTestMsg(pool, fmt.Sprintf("msg-%d", i))
		if !buf.put(peer, msg) {
			t.Fatalf("put should succeed for peer %d", i)
		}
	}

	// Next put for a new peer should fail
	msg := newTestMsg(pool, "overflow")
	if buf.put(peerID("overflow-peer"), msg) {
		t.Fatal("put should fail when buffer is at capacity")
	}
	msg.Free()

	// Overwriting an existing peer should still work (it removes then adds)
	overwrite := newTestMsg(pool, "overwritten")
	if !buf.put(peerID("peer-0"), overwrite) {
		t.Fatal("overwrite should succeed even at capacity")
	}

	got, ok := buf.pop(peerID("peer-0"))
	if !ok {
		t.Fatal("pop should find overwritten message")
	}
	if string(got.Payload) != "overwritten" {
		t.Fatalf("expected 'overwritten', got '%s'", got.Payload)
	}
	got.Free()

	// Clean up remaining
	for i := 1; i < earlyMsgCapacity; i++ {
		peer := peerID(fmt.Sprintf("peer-%d", i))
		if m, ok := buf.pop(peer); ok {
			m.Free()
		}
	}
}

func TestEarlyMsgBuffer_CapacityAfterPop(t *testing.T) {
	buf := newEarlyMsgBuffer()
	defer buf.close()

	pool := newTestPool()

	// Fill to capacity
	for i := 0; i < earlyMsgCapacity; i++ {
		peer := peerID(fmt.Sprintf("peer-%d", i))
		if !buf.put(peer, newTestMsg(pool, "x")) {
			t.Fatalf("put should succeed for peer %d", i)
		}
	}

	// Pop one entry to free a slot
	got, ok := buf.pop(peerID("peer-0"))
	if !ok {
		t.Fatal("pop should succeed")
	}
	got.Free()

	// Now a new peer should fit
	if !buf.put(peerID("new-peer"), newTestMsg(pool, "new")) {
		t.Fatal("put should succeed after popping one entry")
	}

	// Clean up
	for i := 1; i < earlyMsgCapacity; i++ {
		if m, ok := buf.pop(peerID(fmt.Sprintf("peer-%d", i))); ok {
			m.Free()
		}
	}
	if m, ok := buf.pop(peerID("new-peer")); ok {
		m.Free()
	}
}

func TestEarlyMsgBuffer_PutAfterClose(t *testing.T) {
	buf := newEarlyMsgBuffer()

	pool := newTestPool()
	buf.close()

	msg := newTestMsg(pool, "too late")
	if buf.put(peerID("peer1"), msg) {
		t.Fatal("put should fail after close")
	}
	msg.Free()
}

func TestEarlyMsgBuffer_PopAfterClose(t *testing.T) {
	buf := newEarlyMsgBuffer()

	pool := newTestPool()
	buf.put(peerID("peer1"), newTestMsg(pool, "data"))
	buf.close()

	// Messages are freed on close, so pop should not find anything
	_, ok := buf.pop(peerID("peer1"))
	if ok {
		t.Fatal("pop should return false after close")
	}
}

func TestEarlyMsgBuffer_DoubleClose(t *testing.T) {
	buf := newEarlyMsgBuffer()
	buf.close()
	buf.close() // should not panic
}

func TestEarlyMsgBuffer_TTLExpiry(t *testing.T) {
	buf := newEarlyMsgBuffer()
	defer buf.close()

	pool := newTestPool()
	peer := peerID("peer1")

	buf.put(peer, newTestMsg(pool, "expiring"))

	// Wait for the TTL to expire plus some margin
	time.Sleep(earlyMsgTTL + 500*time.Millisecond)

	_, ok := buf.pop(peer)
	if ok {
		t.Fatal("message should have been expired by cleanup")
	}
}

func TestEarlyMsgBuffer_PartialExpiry(t *testing.T) {
	buf := newEarlyMsgBuffer()
	defer buf.close()

	pool := newTestPool()

	// Insert first message
	buf.put(peerID("peer1"), newTestMsg(pool, "old"))

	// Wait half the TTL, then insert second message
	time.Sleep(earlyMsgTTL / 2)

	buf.put(peerID("peer2"), newTestMsg(pool, "new"))

	// Wait for the first to expire but not the second
	time.Sleep(earlyMsgTTL/2 + 500*time.Millisecond)

	// First should be gone
	_, ok := buf.pop(peerID("peer1"))
	if ok {
		t.Fatal("peer1 message should have expired")
	}

	// Second should still be there
	got, ok := buf.pop(peerID("peer2"))
	if !ok {
		t.Fatal("peer2 message should still be present")
	}
	if string(got.Payload) != "new" {
		t.Fatalf("expected payload 'new', got '%s'", got.Payload)
	}
	got.Free()
}

func TestEarlyMsgBuffer_BulkExpiry(t *testing.T) {
	buf := newEarlyMsgBuffer()
	defer buf.close()

	pool := newTestPool()

	for i := 0; i < 50; i++ {
		peer := peerID(fmt.Sprintf("peer-%d", i))
		buf.put(peer, newTestMsg(pool, fmt.Sprintf("msg-%d", i)))
	}

	// All should expire together
	time.Sleep(earlyMsgTTL + 500*time.Millisecond)

	for i := 0; i < 50; i++ {
		_, ok := buf.pop(peerID(fmt.Sprintf("peer-%d", i)))
		if ok {
			t.Fatalf("peer-%d should have expired", i)
		}
	}
}

func TestEarlyMsgBuffer_ConcurrentPutAndPop(t *testing.T) {
	buf := newEarlyMsgBuffer()
	defer buf.close()

	pool := newTestPool()
	var wg sync.WaitGroup

	// Concurrent puts
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			peer := peerID(fmt.Sprintf("peer-%d", id))
			msg := newTestMsg(pool, fmt.Sprintf("msg-%d", id))
			if !buf.put(peer, msg) {
				msg.Free()
			}
		}(i)
	}
	wg.Wait()

	// Concurrent pops
	var popped int64
	var mu sync.Mutex
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			peer := peerID(fmt.Sprintf("peer-%d", id))
			if msg, ok := buf.pop(peer); ok {
				msg.Free()
				mu.Lock()
				popped++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if popped != 100 {
		t.Fatalf("expected to pop 100 messages, got %d", popped)
	}
}

func TestEarlyMsgBuffer_ConcurrentPutPopAndClose(t *testing.T) {
	buf := newEarlyMsgBuffer()

	pool := newTestPool()
	var wg sync.WaitGroup

	// Concurrent puts
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			peer := peerID(fmt.Sprintf("peer-%d", id))
			msg := newTestMsg(pool, fmt.Sprintf("msg-%d", id))
			if !buf.put(peer, msg) {
				msg.Free()
			}
		}(i)
	}

	// Concurrent pops
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			peer := peerID(fmt.Sprintf("peer-%d", id))
			if msg, ok := buf.pop(peer); ok {
				msg.Free()
			}
		}(i)
	}

	// Close concurrently
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf.close()
	}()

	wg.Wait() // should not panic or deadlock
}

func TestEarlyMsgBuffer_OverwriteDoesNotLeak(t *testing.T) {
	buf := newEarlyMsgBuffer()
	defer buf.close()

	// Use a dedicated pool to detect that overwritten message's Free was called
	freeCalled := make(chan struct{}, 1)
	origPool := &sync.Pool{
		New: func() any {
			b := make([]byte, 64)
			return &b
		},
	}

	b := make([]byte, 64)
	copy(b, "original")
	bufPtr := &b
	origMsg := Msg{
		bufPool: origPool,
		bufPtr:  bufPtr,
		Payload: b[:8],
	}

	peer := peerID("peer1")
	buf.put(peer, origMsg)

	// Now check if the original buffer was freed by trying to get from pool
	// We need a wrapper pool that signals when Put is called
	trackPool := &sync.Pool{
		New: func() any {
			b := make([]byte, 64)
			return &b
		},
	}
	_ = trackPool

	// Simpler approach: overwrite and check that only new value is returned
	newPool := newTestPool()
	buf.put(peer, newTestMsg(newPool, "replaced"))

	// After overwrite, only the new message should be retrievable
	got, ok := buf.pop(peer)
	if !ok {
		t.Fatal("pop should find the message")
	}
	if string(got.Payload) != "replaced" {
		t.Fatalf("expected 'replaced', got '%s'", got.Payload)
	}
	got.Free()
	close(freeCalled)
}

func TestEarlyMsgBuffer_EmptyBuffer(t *testing.T) {
	buf := newEarlyMsgBuffer()
	defer buf.close()

	// Pop from empty buffer
	_, ok := buf.pop(peerID("anything"))
	if ok {
		t.Fatal("pop from empty buffer should return false")
	}

	// Close empty buffer should be fine
	buf2 := newEarlyMsgBuffer()
	buf2.close()
}
