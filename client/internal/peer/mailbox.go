package peer

import (
	"sync"
)

// maxQueuedCandidates bounds the remote candidate queue; on overflow the
// oldest candidate is dropped. Lost candidates are recovered by the next
// offer exchange triggered by the guard.
const maxQueuedCandidates = 128

// mailbox is the coalescing inbox of the Conn event loop. Posting never
// blocks. Per message kind either the latest value wins (offer, answer,
// guard tick), the values queue in bounded FIFO order (candidates) or in
// unbounded FIFO order (lifecycle and transport state changes, which are
// low-volume and must not be lost). A new offer flushes the queued
// candidates because they belong to the superseded session.
type mailbox struct {
	mu     sync.Mutex
	closed bool

	lifecycle  []event
	transport  []event
	offer      *evRemoteOffer
	answer     *evRemoteAnswer
	candidates []evRemoteCandidate
	guardTick  bool

	wake chan struct{}
}

func newMailbox() *mailbox {
	return &mailbox{
		wake: make(chan struct{}, 1),
	}
}

// post stores the event and wakes the loop. It reports false if the mailbox
// is already closed and the event was not accepted.
func (m *mailbox) post(ev event) bool {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return false
	}

	switch e := ev.(type) {
	case evClose:
		m.lifecycle = append(m.lifecycle, e)
	case evRemoteOffer:
		m.offer = &e
		m.candidates = nil
	case evRemoteAnswer:
		m.answer = &e
	case evRemoteCandidate:
		if len(m.candidates) >= maxQueuedCandidates {
			m.candidates = m.candidates[1:]
		}
		m.candidates = append(m.candidates, e)
	case evGuardTick:
		m.guardTick = true
	default:
		m.transport = append(m.transport, ev)
	}
	m.mu.Unlock()

	select {
	case m.wake <- struct{}{}:
	default:
	}
	return true
}

// drain returns the pending events in processing order: lifecycle first,
// then transport state changes, the coalesced offer and answer, the queued
// candidates and finally the guard tick.
func (m *mailbox) drain() []event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.drainLocked()
}

// closeAndDrain marks the mailbox closed so further posts are rejected and
// returns the events that were still pending.
func (m *mailbox) closeAndDrain() []event {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return m.drainLocked()
}

func (m *mailbox) drainLocked() []event {
	evs := make([]event, 0, len(m.lifecycle)+len(m.transport)+len(m.candidates)+3)
	evs = append(evs, m.lifecycle...)
	evs = append(evs, m.transport...)
	if m.offer != nil {
		evs = append(evs, *m.offer)
	}
	if m.answer != nil {
		evs = append(evs, *m.answer)
	}
	for _, c := range m.candidates {
		evs = append(evs, c)
	}
	if m.guardTick {
		evs = append(evs, evGuardTick{})
	}

	m.lifecycle = nil
	m.transport = nil
	m.offer = nil
	m.answer = nil
	m.candidates = nil
	m.guardTick = false
	return evs
}
