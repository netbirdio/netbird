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
	// reached the oldest outstanding request is forgotten and its response is
	// routed like one with an unknown transaction ID. Recently answered owners
	// have a separate cap of the same size.
	maxTransactions = 4096

	stunHeaderSize = 20
)

type transactionID [stun.TransactionIDSize]byte

type trackedTransaction struct {
	conn    *udpMuxedConn
	seq     uint64
	expires time.Time
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
	// Records replaced by a resend or consumed by a response stay queued, with a
	// sequence number no longer matching their entry, until they reach the head
	// or the queue is compacted.
	queue []queuedTransaction
	// Duplicate responses must keep their owner: fallback could let a different
	// candidate consume the agent's pending check before the first copy is read.
	// Recent records have their own cap so they cannot evict pending checks.
	recent      map[transactionID]trackedTransaction
	recentQueue []queuedTransaction
	seq         uint64
	ttl         time.Duration
	max         int
}

func newTransactionTracker(ttl time.Duration, maxEntries int) *transactionTracker {
	return &transactionTracker{
		entries: make(map[transactionID]trackedTransaction),
		recent:  make(map[transactionID]trackedTransaction),
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
	bodyLength := int(binary.BigEndian.Uint16(b[2:4]))
	if bodyLength%4 != 0 || bodyLength > len(b)-stunHeaderSize {
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

// record returns a rollback token for a new registration. A retransmission on
// the same conn returns zero: a send error cannot invalidate its earlier check.
func (t *transactionTracker) record(id transactionID, conn *udpMuxedConn, now time.Time) uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()

	// A write can race RemoveConnByUfrag or Close; recording it for a closed
	// conn would leave a record the removal has already passed.
	if conn.isClosed() {
		return 0
	}

	t.pruneExpired(now)
	previous, exists := t.entries[id]
	if !exists && len(t.entries) >= t.max {
		t.evictOldest()
	}
	if !exists {
		previous, exists = t.recent[id]
		exists = exists && previous.expires.After(now)
	}
	delete(t.recent, id)

	t.seq++
	t.entries[id] = trackedTransaction{conn: conn, seq: t.seq, expires: now.Add(t.ttl)}
	t.queue = append(t.queue, queuedTransaction{id: id, seq: t.seq, expires: now.Add(t.ttl)})

	// Answered requests leave their queue records behind; compacting at twice
	// the cap keeps the queue bounded by the cap, not by the send rate.
	if len(t.queue) > 2*t.max {
		t.compact()
	}
	if exists && previous.conn == conn {
		return 0
	}
	return t.seq
}

// take removes a pending request and retains its owner until the original
// expiry. Duplicate responses keep that owner without extending its lifetime.
func (t *transactionTracker) take(id transactionID, now time.Time) *udpMuxedConn {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.pruneExpired(now)
	entry, ok := t.entries[id]
	if ok {
		delete(t.entries, id)
		t.rememberResponse(id, entry)
		return entry.conn
	}
	if entry, ok = t.recent[id]; ok && entry.expires.After(now) {
		return entry.conn
	}
	delete(t.recent, id)
	return nil
}

func (t *transactionTracker) rememberResponse(id transactionID, entry trackedTransaction) {
	for len(t.recent) >= t.max {
		head := t.recentQueue[0]
		t.recentQueue = t.recentQueue[1:]
		if current, ok := t.recent[head.id]; ok && current.seq == head.seq {
			delete(t.recent, head.id)
		}
	}
	t.recent[id] = entry
	t.recentQueue = append(t.recentQueue, queuedTransaction{id: id, seq: entry.seq})
	if len(t.recentQueue) > 2*t.max {
		t.compactRecent()
	}
}

// Response arrival order differs from request expiry order. Lookup checks the
// original deadline directly; the idle worker sweeps this bounded map.
func (t *transactionTracker) pruneRecent(now time.Time) {
	for id, entry := range t.recent {
		if !entry.expires.After(now) {
			delete(t.recent, id)
		}
	}
	t.compactRecent()
}

func (t *transactionTracker) compactRecent() {
	live := make([]queuedTransaction, 0, len(t.recent))
	for _, q := range t.recentQueue {
		if entry, ok := t.recent[q.id]; ok && entry.seq == q.seq {
			live = append(live, q)
		}
	}
	t.recentQueue = live
}

// A failed write must not erase a later retransmission, even on the same conn.
func (t *transactionTracker) forget(id transactionID, conn *udpMuxedConn, seq uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if entry, ok := t.entries[id]; ok && entry.conn == conn && entry.seq == seq {
		delete(t.entries, id)
	}
}

// removeConn forgets every request sent by conn.
func (t *transactionTracker) removeConn(conn *udpMuxedConn) {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, entries := range []map[transactionID]trackedTransaction{t.entries, t.recent} {
		for id, entry := range entries {
			if entry.conn == conn {
				delete(entries, id)
			}
		}
	}
}

// clear forgets every request.
func (t *transactionTracker) clear() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.entries = make(map[transactionID]trackedTransaction)
	t.queue = nil
	t.recent = make(map[transactionID]trackedTransaction)
	t.recentQueue = nil
}

func (t *transactionTracker) pruneExpired(now time.Time) {
	for len(t.queue) > 0 && !t.queue[0].expires.After(now) {
		t.popHead()
	}
}

// evictOldest forgets the oldest outstanding request, skipping stale records.
func (t *transactionTracker) evictOldest() {
	for len(t.queue) > 0 {
		if t.popHead() {
			return
		}
	}
}

// popHead removes the oldest queue record and reports whether it was still
// outstanding.
func (t *transactionTracker) popHead() bool {
	head := t.queue[0]
	t.queue = t.queue[1:]
	if !t.isLive(head) {
		return false
	}
	delete(t.entries, head.id)
	return true
}

func (t *transactionTracker) compact() {
	live := make([]queuedTransaction, 0, len(t.entries))
	for _, q := range t.queue {
		if t.isLive(q) {
			live = append(live, q)
		}
	}
	t.queue = live
}

func (t *transactionTracker) isLive(q queuedTransaction) bool {
	entry, ok := t.entries[q.id]
	return ok && entry.seq == q.seq
}

// Idle muxes must release expired entries without waiting for another packet.
func (m *SingleSocketUDPMux) expireTransactions() {
	defer close(m.transactionsDone)
	ticker := time.NewTicker(transactionTTL)
	defer ticker.Stop()
	for {
		select {
		case <-m.closedChan:
			return
		case now := <-ticker.C:
			m.transactions.mu.Lock()
			m.transactions.pruneExpired(now)
			m.transactions.pruneRecent(now)
			m.transactions.mu.Unlock()
		}
	}
}
