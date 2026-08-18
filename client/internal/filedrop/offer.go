package filedrop

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Offer is one incoming transfer as tracked by the receiver.
type Offer struct {
	ID         OfferID
	Sender     PeerKey
	SenderName string
	Files      []FileMeta
	Decision   Decision
	State      State
	CreatedAt  time.Time
	ExpiresAt  time.Time
	Progress   []int64
}

type offerEntry struct {
	offer   Offer
	decided chan struct{}
}

// OfferStore tracks incoming offers and their decisions.
type OfferStore struct {
	mu      sync.RWMutex
	offers  map[OfferID]*offerEntry
	ttl     time.Duration
	newID   func() OfferID
	nowFunc func() time.Time
}

// NewOfferStore returns an empty store using ttl as the decision deadline.
func NewOfferStore(ttl time.Duration) *OfferStore {
	if ttl <= 0 {
		ttl = DefaultOfferTTL
	}
	return &OfferStore{
		offers:  make(map[OfferID]*offerEntry),
		ttl:     ttl,
		newID:   func() OfferID { return OfferID(uuid.NewString()) },
		nowFunc: time.Now,
	}
}

// Add registers a new offer with the given initial decision and returns its snapshot.
func (s *OfferStore) Add(sender PeerKey, senderName string, files []FileMeta, decision Decision) Offer {
	now := s.nowFunc()

	entry := &offerEntry{
		offer: Offer{
			ID:         s.newID(),
			Sender:     sender,
			SenderName: senderName,
			Files:      files,
			Decision:   decision,
			State:      stateForDecision(decision),
			CreatedAt:  now,
			ExpiresAt:  now.Add(s.ttl),
			Progress:   make([]int64, len(files)),
		},
		decided: make(chan struct{}),
	}
	if decision != DecisionPending {
		close(entry.decided)
	}

	s.mu.Lock()
	s.offers[entry.offer.ID] = entry
	s.mu.Unlock()

	return entry.offer.clone()
}

// Get returns a snapshot of one offer belonging to sender.
func (s *OfferStore) Get(sender PeerKey, id OfferID) (Offer, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, ok := s.offers[id]
	if !ok || entry.offer.Sender != sender {
		return Offer{}, false
	}
	return entry.offer.clone(), true
}

// List returns snapshots of every tracked offer.
func (s *OfferStore) List() []Offer {
	s.mu.RLock()
	defer s.mu.RUnlock()

	offers := make([]Offer, 0, len(s.offers))
	for _, entry := range s.offers {
		offers = append(offers, entry.offer.clone())
	}
	return offers
}

// Decide records the receiver's answer; a made decision is final.
func (s *OfferStore) Decide(id OfferID, decision Decision) (Offer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.offers[id]
	if !ok || entry.offer.Decision != DecisionPending {
		return Offer{}, false
	}

	entry.offer.Decision = decision
	entry.offer.State = stateForDecision(decision)
	if decision == DecisionAccepted && entry.offer.awaitsNoUpload() {
		entry.offer.State = StateCompleted
	}
	close(entry.decided)

	return entry.offer.clone(), true
}

// Revoke withdraws consent for an offer whatever it has already answered, so an
// upload in flight can be stopped. Decide only moves an offer out of Pending: a
// transfer that is already running has no way back through it.
func (s *OfferStore) Revoke(id OfferID) (Offer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.offers[id]
	if !ok {
		return Offer{}, false
	}

	// An offer still waiting has a reader parked on its channel; one that was
	// answered has already had it closed, and closing twice would panic.
	if entry.offer.Decision == DecisionPending {
		close(entry.decided)
	}

	entry.offer.Decision = DecisionDeclined
	entry.offer.State = StateCancelled

	return entry.offer.clone(), true
}

// Await blocks until a decision, expiry, or ctx cancellation.
func (s *OfferStore) Await(ctx context.Context, sender PeerKey, id OfferID) (Offer, error) {
	s.mu.RLock()
	entry, ok := s.offers[id]
	if ok && entry.offer.Sender != sender {
		ok = false
	}
	var decided chan struct{}
	var expiresAt time.Time
	if ok {
		decided = entry.decided
		expiresAt = entry.offer.ExpiresAt
	}
	s.mu.RUnlock()

	if !ok {
		return Offer{}, ErrOfferNotFound
	}

	timer := time.NewTimer(time.Until(expiresAt))
	defer timer.Stop()

	select {
	case <-decided:
	case <-timer.C:
		s.Decide(id, DecisionExpired)
	case <-ctx.Done():
		offer, _ := s.Get(sender, id)
		return offer, ctx.Err()
	}

	offer, ok := s.Get(sender, id)
	if !ok {
		return Offer{}, ErrOfferNotFound
	}
	return offer, nil
}

// SetProgress records the staged byte count for one file of an offer.
func (s *OfferStore) SetProgress(id OfferID, index int, received int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.offers[id]
	if !ok || index < 0 || index >= len(entry.offer.Progress) {
		return
	}
	entry.offer.Progress[index] = received
	if entry.offer.State == StatePending {
		entry.offer.State = StateTransferring
	}
}

// SetState overrides the transfer state, for completion and failure reporting.
func (s *OfferStore) SetState(id OfferID, state State) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if entry, ok := s.offers[id]; ok {
		entry.offer.State = state
	}
}

// Remove drops an offer from the store.
func (s *OfferStore) Remove(id OfferID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.offers, id)
}

// ExpireOverdue marks every pending offer past its deadline as expired and returns them.
func (s *OfferStore) ExpireOverdue() []Offer {
	now := s.nowFunc()

	s.mu.Lock()
	defer s.mu.Unlock()

	var expired []Offer
	for _, entry := range s.offers {
		if entry.offer.Decision != DecisionPending || now.Before(entry.offer.ExpiresAt) {
			continue
		}
		entry.offer.Decision = DecisionExpired
		entry.offer.State = StateExpired
		close(entry.decided)
		expired = append(expired, entry.offer.clone())
	}
	return expired
}

// Complete marks an offer completed once every file reached its announced size.
func (s *OfferStore) Complete(id OfferID) (Offer, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.offers[id]
	if !ok || entry.offer.State == StateCompleted {
		return Offer{}, false
	}

	if !entry.offer.fullyStaged() {
		return Offer{}, false
	}

	entry.offer.State = StateCompleted
	return entry.offer.clone(), true
}

func (o Offer) awaitsNoUpload() bool {
	for _, f := range o.Files {
		if f.Kind != KindText {
			return false
		}
	}
	return true
}

func (o Offer) fullyStaged() bool {
	for i, f := range o.Files {
		if f.Kind == KindText {
			continue
		}
		if i >= len(o.Progress) || o.Progress[i] < f.Size {
			return false
		}
	}
	return true
}

func (o Offer) clone() Offer {
	c := o
	c.Files = make([]FileMeta, len(o.Files))
	copy(c.Files, o.Files)
	c.Progress = make([]int64, len(o.Progress))
	copy(c.Progress, o.Progress)
	return c
}

// TotalSize is the announced byte count across every file of the offer.
func (o Offer) TotalSize() int64 {
	var total int64
	for _, f := range o.Files {
		total += f.Size
	}
	return total
}

func stateForDecision(d Decision) State {
	switch d {
	case DecisionAccepted:
		return StateTransferring
	case DecisionDeclined:
		return StateDeclined
	case DecisionExpired:
		return StateExpired
	default:
		return StatePending
	}
}
