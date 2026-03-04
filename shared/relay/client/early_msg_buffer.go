package client

import (
	"container/list"
	"sync"
	"time"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	earlyMsgTTL      = 5 * time.Second
	earlyMsgCapacity = 1000
)

// earlyMsgBuffer buffers transport messages that arrive before the corresponding
// OpenConn call. This happens during reconnection when the remote peer sends data
// before the local side has set up the relay connection.
//
// It stores at most one message per peer (the first WireGuard handshake) and
// caps the total number of entries to prevent unbounded memory growth.
// A cleanup timer runs only when there are buffered entries and fires when the
// oldest entry expires. Entries are kept in a linked list ordered by insertion
// time so cleanup only needs to walk from the front.
type earlyMsgBuffer struct {
	mu     sync.Mutex
	index  map[messages.PeerID]*list.Element
	order  *list.List // front = oldest
	timer  *time.Timer
	closed bool
}

type earlyMsg struct {
	peerID    messages.PeerID
	msg       Msg
	createdAt time.Time
}

func newEarlyMsgBuffer() *earlyMsgBuffer {
	return &earlyMsgBuffer{
		index: make(map[messages.PeerID]*list.Element),
		order: list.New(),
	}
}

// put stores or overwrites a message for the given peer. If a message for the
// peer already exists, it is replaced with the new one. Returns false if the
// message was not stored (buffer full or buffer closed).
func (b *earlyMsgBuffer) put(peerID messages.PeerID, msg Msg) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return false
	}

	if existing, exists := b.index[peerID]; exists {
		old := b.order.Remove(existing).(earlyMsg)
		old.msg.Free()
		delete(b.index, peerID)
	}

	if b.order.Len() >= earlyMsgCapacity {
		return false
	}

	entry := earlyMsg{
		peerID: peerID,
		msg: msg,
		createdAt: time.Now(),
	}
	elem := b.order.PushBack(entry)
	b.index[peerID] = elem

	// Start the cleanup timer if this is the first entry
	if b.order.Len() == 1 {
		b.scheduleCleanup(earlyMsgTTL)
	}

	return true
}

// pop retrieves and removes the buffered message for the given peer.
// Returns the message and true if found, zero value and false otherwise.
func (b *earlyMsgBuffer) pop(peerID messages.PeerID) (Msg, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	elem, ok := b.index[peerID]
	if !ok {
		return Msg{}, false
	}

	entry := b.order.Remove(elem).(earlyMsg)
	delete(b.index, peerID)

	if b.order.Len() == 0 {
		b.stopCleanup()
	}

	return entry.msg, true
}

// close stops the cleanup timer and frees all buffered messages.
func (b *earlyMsgBuffer) close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}
	b.closed = true
	b.stopCleanup()

	for elem := b.order.Front(); elem != nil; elem = elem.Next() {
		entry := elem.Value.(earlyMsg)
		entry.msg.Free()
	}
	b.order.Init()
	b.index = make(map[messages.PeerID]*list.Element)
}

// scheduleCleanup starts or resets the timer. Caller must hold b.mu.
func (b *earlyMsgBuffer) scheduleCleanup(d time.Duration) {
	if b.timer != nil {
		b.timer.Stop()
	}
	b.timer = time.AfterFunc(d, b.removeExpired)
}

// stopCleanup stops the timer. Caller must hold b.mu.
func (b *earlyMsgBuffer) stopCleanup() {
	if b.timer != nil {
		b.timer.Stop()
		b.timer = nil
	}
}

func (b *earlyMsgBuffer) removeExpired() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}

	now := time.Now()
	for elem := b.order.Front(); elem != nil; {
		entry := elem.Value.(earlyMsg)
		if now.Sub(entry.createdAt) <= earlyMsgTTL {
			// Entries are ordered by time, so the rest are newer
			break
		}
		next := elem.Next()
		b.order.Remove(elem)
		delete(b.index, entry.peerID)
		entry.msg.Free()
		elem = next
	}

	if b.order.Len() == 0 {
		b.timer = nil
		return
	}

	// Schedule next cleanup based on when the oldest entry expires
	front := b.order.Front()
	if front == nil {
		b.timer = nil
		return
	}
	oldest := front.Value.(earlyMsg).createdAt
	nextCleanup := earlyMsgTTL - now.Sub(oldest)
	b.scheduleCleanup(nextCleanup)
}
