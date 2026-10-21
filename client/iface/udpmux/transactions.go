package udpmux

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/pion/stun/v3"
)

const (
	// transactionTTL is how long a request waits for its response. The ICE agent
	// drops a pending binding request after 4 seconds, so later responses are
	// discarded by the agent regardless of where they are delivered.
	transactionTTL = 5 * time.Second

	// maxTransactions caps the outstanding requests the mux remembers. When it is
	// reached the oldest request is forgotten and its response takes the
	// address-based fallback.
	maxTransactions = 4096

	stunHeaderSize = 20
)

type transactionID [stun.TransactionIDSize]byte

type trackedTransaction struct {
	conn *udpMuxedConn
	seq  uint64
}

type queuedTransaction struct {
	id      transactionID
	seq     uint64
	expires time.Time
}

// transactionTracker remembers which muxed conn sent each outstanding STUN
// request, so the response is delivered to that conn alone.
type transactionTracker struct {
	mu      sync.Mutex
	entries map[transactionID]trackedTransaction
	// queue holds every record in insertion order, which is also expiry order.
	// Records replaced by a resend or consumed by a response stay queued until
	// they reach the head, where their sequence number no longer matches.
	queue []queuedTransaction
	seq   uint64
	ttl   time.Duration
	max   int
}

func newTransactionTracker(ttl time.Duration, maxEntries int) *transactionTracker {
	return &transactionTracker{
		entries: make(map[transactionID]trackedTransaction),
		ttl:     ttl,
		max:     maxEntries,
	}
}

// stunRequestTransactionID reads the transaction ID of a STUN request from the
// header alone (RFC 8489 section 5), without decoding the attributes.
func stunRequestTransactionID(b []byte) (transactionID, bool) {
	if len(b) < stunHeaderSize || b[0]&0xc0 != 0 || !stun.IsMessage(b) {
		return transactionID{}, false
	}

	var msgType stun.MessageType
	msgType.ReadValue(binary.BigEndian.Uint16(b[0:2]))
	if msgType.Class != stun.ClassRequest {
		return transactionID{}, false
	}

	var id transactionID
	copy(id[:], b[8:stunHeaderSize])
	return id, true
}

// record notes that conn sent the request id. Sending the same id again
// refreshes the record and moves it to conn.
func (t *transactionTracker) record(id transactionID, conn *udpMuxedConn, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.pruneExpired(now)
	if len(t.queue) >= t.max {
		t.popHead()
	}

	t.seq++
	t.entries[id] = trackedTransaction{conn: conn, seq: t.seq}
	t.queue = append(t.queue, queuedTransaction{id: id, seq: t.seq, expires: now.Add(t.ttl)})
}

// take returns the conn that sent request id and forgets the request, or nil
// when the request is unknown or expired.
func (t *transactionTracker) take(id transactionID, now time.Time) *udpMuxedConn {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.pruneExpired(now)
	entry, ok := t.entries[id]
	if !ok {
		return nil
	}
	delete(t.entries, id)
	return entry.conn
}

// removeConn forgets every request sent by conn.
func (t *transactionTracker) removeConn(conn *udpMuxedConn) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for id, entry := range t.entries {
		if entry.conn == conn {
			delete(t.entries, id)
		}
	}
}

// clear forgets every request.
func (t *transactionTracker) clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.entries = make(map[transactionID]trackedTransaction)
	t.queue = nil
}

func (t *transactionTracker) pending() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

func (t *transactionTracker) pruneExpired(now time.Time) {
	for len(t.queue) > 0 && !t.queue[0].expires.After(now) {
		t.popHead()
	}
}

func (t *transactionTracker) popHead() {
	head := t.queue[0]
	t.queue = t.queue[1:]
	if entry, ok := t.entries[head.id]; ok && entry.seq == head.seq {
		delete(t.entries, head.id)
	}
}
