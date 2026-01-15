package oidc

import (
	"sync"
	"time"
)

const (
	// StateExpiration is how long OIDC state tokens are valid
	StateExpiration = 10 * time.Minute
)

// StateStore manages OIDC state tokens for CSRF protection
type StateStore struct {
	mu     sync.RWMutex
	states map[string]*State
}

// NewStateStore creates a new OIDC state store
func NewStateStore() *StateStore {
	return &StateStore{
		states: make(map[string]*State),
	}
}

// Store saves a state token with associated metadata
func (s *StateStore) Store(stateToken, originalURL, routeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.states[stateToken] = &State{
		OriginalURL: originalURL,
		CreatedAt:   time.Now(),
		RouteID:     routeID,
	}

	// Clean up expired states
	s.cleanup()
}

// Get retrieves a state by token
func (s *StateStore) Get(stateToken string) (*State, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	st, ok := s.states[stateToken]
	return st, ok
}

// Delete removes a state token
func (s *StateStore) Delete(stateToken string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.states, stateToken)
}

// cleanup removes expired state tokens (must be called with lock held)
func (s *StateStore) cleanup() {
	cutoff := time.Now().Add(-StateExpiration)
	for k, v := range s.states {
		if v.CreatedAt.Before(cutoff) {
			delete(s.states, k)
		}
	}
}
