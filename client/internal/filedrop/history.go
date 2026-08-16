package filedrop

import (
	"fmt"
	"slices"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// The transfer directions.
const (
	DirectionReceived Direction = iota
	DirectionSent
)

// The failure reasons a transfer can end with; None accompanies every other state.
const (
	ReasonNone FailureReason = iota
	// ReasonUnreachable marks a transport-level failure: nothing listens on the
	// peer's file drop port, so the client is old or receiving is off.
	ReasonUnreachable
	// ReasonInterrupted marks a transfer that was still moving when the process
	// stopped; nothing survived to finish or resume it.
	ReasonInterrupted
)

const historyCap = 30

// Direction tells whether a transfer was sent by this device or received on it.
type Direction uint8

// FailureReason classifies why a transfer failed, when it is known.
type FailureReason uint8

// String implements fmt.Stringer.
func (d Direction) String() string {
	switch d {
	case DirectionReceived:
		return "received"
	case DirectionSent:
		return "sent"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(d))
	}
}

// Transfer is one history entry: a sent or received offer with its outcome.
type Transfer struct {
	ID             OfferID       `json:"id"`
	Direction      Direction     `json:"direction"`
	PeerKey        PeerKey       `json:"peerKey"`
	PeerName       string        `json:"peerName"`
	Files          []FileMeta    `json:"files"`
	State          State         `json:"state"`
	Transferred    int64         `json:"transferred"`
	TotalSize      int64         `json:"totalSize"`
	CreatedAt      time.Time     `json:"createdAt"`
	UpdatedAt      time.Time     `json:"updatedAt"`
	DeliveredPaths []string      `json:"deliveredPaths,omitempty"`
	Error          string        `json:"error,omitempty"`
	Reason         FailureReason `json:"reason,omitempty"`
}

// History is the persisted transfer log of one profile, newest first.
type History struct {
	mu      sync.RWMutex
	store   Store
	entries []Transfer
}

// LoadHistory reads the stored transfer log, starting empty when unreadable.
func LoadHistory(store Store) *History {
	h := &History{store: store}

	var entries []Transfer
	if err := loadSection(store, namespaceHistory, &entries); err != nil {
		log.Warnf("failed to read file drop history, starting empty: %v", err)
		return h
	}
	h.entries = entries
	if h.settleInterrupted() {
		h.persist()
	}
	return h
}

func (t Transfer) terminal() bool {
	switch t.State {
	case StateCompleted, StateDeclined, StateExpired, StateCancelled, StateFailed:
		return true
	default:
		return false
	}
}

func (t Transfer) clone() Transfer {
	c := t
	c.Files = slices.Clone(t.Files)
	c.DeliveredPaths = slices.Clone(t.DeliveredPaths)
	return c
}

// Upsert inserts or replaces the entry with the same ID and persists the log.
func (h *History) Upsert(t Transfer) {
	t.UpdatedAt = time.Now()

	h.mu.Lock()
	defer h.mu.Unlock()

	if i := h.indexOf(t.ID); i >= 0 {
		h.entries[i] = t
	} else {
		h.entries = slices.Insert(h.entries, 0, t)
		h.prune()
	}
	h.persist()
}

// SetProgress updates the transferred byte count in memory only.
func (h *History) SetProgress(id OfferID, transferred int64) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if i := h.indexOf(id); i >= 0 {
		h.entries[i].Transferred = transferred
		h.entries[i].UpdatedAt = time.Now()
		if h.entries[i].State == StatePending {
			h.entries[i].State = StateTransferring
		}
	}
}

// Get returns the entry with the given ID.
func (h *History) Get(id OfferID) (Transfer, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if i := h.indexOf(id); i >= 0 {
		return h.entries[i].clone(), true
	}
	return Transfer{}, false
}

// List returns every entry, newest first.
func (h *History) List() []Transfer {
	h.mu.RLock()
	defer h.mu.RUnlock()

	list := make([]Transfer, len(h.entries))
	for i, e := range h.entries {
		list[i] = e.clone()
	}
	return list
}

// Delete removes one entry and persists the log.
func (h *History) Delete(id OfferID) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if i := h.indexOf(id); i >= 0 {
		h.entries = slices.Delete(h.entries, i, i+1)
		h.persist()
	}
}

func (h *History) indexOf(id OfferID) int {
	return slices.IndexFunc(h.entries, func(t Transfer) bool { return t.ID == id })
}

func (h *History) prune() {
	if len(h.entries) <= historyCap {
		return
	}
	for i := len(h.entries) - 1; i >= 0 && len(h.entries) > historyCap; i-- {
		if h.entries[i].terminal() {
			h.entries = slices.Delete(h.entries, i, i+1)
		}
	}
}

// settleInterrupted closes out transfers that were still moving when the
// process died. Nothing is left to finish them, so left alone they would sit in
// the log as permanently pending. Reports whether anything changed.
func (h *History) settleInterrupted() bool {
	changed := false
	for i, t := range h.entries {
		if t.terminal() {
			continue
		}
		h.entries[i].State = StateFailed
		h.entries[i].Reason = ReasonInterrupted
		h.entries[i].UpdatedAt = time.Now()
		changed = true
	}
	return changed
}

func (h *History) persist() {
	if err := saveSection(h.store, namespaceHistory, h.entries); err != nil {
		log.Warnf("failed to write file drop history: %v", err)
	}
}
