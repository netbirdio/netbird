package grpc

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// AttestationSession holds the server-side state for a pending TPM credential activation.
// The server generates a credential challenge (MakeCredential) and stores the expected
// secret alongside the peer's CSR. The peer must decrypt the challenge using its TPM
// (ActivateCredential) and return the secret to complete attestation.
type AttestationSession struct {
	// ExpectedSecret is the plaintext secret the server wrapped in the credential
	// challenge. The peer must return this exact value to prove TPM possession.
	ExpectedSecret []byte
	// CSRPEM is the PEM-encoded certificate signing request submitted by the peer.
	CSRPEM string
	// WGKey is the peer's WireGuard public key.
	WGKey string
	// AccountID is the account the peer belongs to.
	AccountID string
	// ExpiresAt is when the session becomes invalid. Get returns (_, false) after this time.
	ExpiresAt time.Time
}

// maxAttestationSessions is the maximum number of concurrent pending attestation sessions.
// Enforced in Put to prevent memory exhaustion via unauthenticated BeginTPMAttestation calls.
const maxAttestationSessions = 10_000

// AttestationSessionStore is a concurrency-safe in-memory store for pending attestation
// sessions. Sessions expire after their ExpiresAt time. They do not survive process restart.
//
// Always create with NewAttestationSessionStore; do not use the zero value directly.
type AttestationSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]AttestationSession
}

// NewAttestationSessionStore returns a ready-to-use AttestationSessionStore.
func NewAttestationSessionStore() *AttestationSessionStore {
	return &AttestationSessionStore{
		sessions: make(map[string]AttestationSession),
	}
}

// Put stores a session under the given ID, replacing any existing entry.
//
// When the store is at capacity, expired sessions are evicted first. If the store
// is still full after eviction, an error is returned to prevent memory exhaustion
// via unauthenticated BeginTPMAttestation requests.
func (s *AttestationSessionStore) Put(id string, sess AttestationSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.sessions) >= maxAttestationSessions {
		// Evict expired sessions before rejecting new ones. This prevents the store
		// from staying at capacity just because the cleanup goroutine hasn't run yet.
		now := time.Now()
		for k, v := range s.sessions {
			if now.After(v.ExpiresAt) {
				delete(s.sessions, k)
			}
		}
		if len(s.sessions) >= maxAttestationSessions {
			return fmt.Errorf("attestation session store at capacity (%d), try again later", maxAttestationSessions)
		}
	}
	s.sessions[id] = sess
	return nil
}

// Get returns the session for id. Returns (_, false) if the session does not exist or
// has passed its ExpiresAt deadline. Expired sessions are not removed from the map here;
// use cleanup or Delete for removal.
func (s *AttestationSessionStore) Get(id string) (AttestationSession, bool) {
	s.mu.RLock()
	sess, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok || time.Now().After(sess.ExpiresAt) {
		return AttestationSession{}, false
	}
	return sess, true
}

// Delete removes the session for id. A no-op if the session does not exist.
func (s *AttestationSessionStore) Delete(id string) {
	s.mu.Lock()
	delete(s.sessions, id)
	s.mu.Unlock()
}

// GetAndDelete atomically retrieves and removes the session for id.
// Returns (_, false) if the session does not exist or has expired.
//
// Using GetAndDelete instead of separate Get + Delete is required for
// CompleteTPMAttestation: it prevents two concurrent requests with the
// same session ID from both passing the existence check and both
// proceeding to issue a certificate (TOCTOU race).
func (s *AttestationSessionStore) GetAndDelete(id string) (AttestationSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok || time.Now().After(sess.ExpiresAt) {
		delete(s.sessions, id) // clean up expired entry if present
		return AttestationSession{}, false
	}
	delete(s.sessions, id)
	return sess, true
}

// StartCleanup launches a background goroutine that removes expired sessions every interval.
// The goroutine stops when ctx is cancelled. Callers should start cleanup once at server
// startup with a suitable interval (e.g. 5 * time.Minute).
func (s *AttestationSessionStore) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.cleanup()
			}
		}
	}()
}

// cleanup removes all sessions whose ExpiresAt is in the past.
func (s *AttestationSessionStore) cleanup() {
	now := time.Now()
	s.mu.Lock()
	for id, sess := range s.sessions {
		if now.After(sess.ExpiresAt) {
			delete(s.sessions, id)
		}
	}
	s.mu.Unlock()
}
