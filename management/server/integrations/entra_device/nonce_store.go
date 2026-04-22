package entra_device

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

// DefaultNonceTTL is the lifetime of a challenge nonce.
const DefaultNonceTTL = 60 * time.Second

// NonceStore issues and consumes single-use nonces. The implementation stores
// nonces in memory. For multi-node management deployments a Redis-backed
// implementation can replace this with the same interface.
type NonceStore interface {
	// Issue produces a new random nonce with the configured TTL.
	Issue() (nonce string, expiresAt time.Time, err error)
	// Consume validates that nonce exists and removes it atomically.
	// Returns (true, nil) on success, (false, nil) if not found / expired,
	// and a non-nil error only on unexpected conditions.
	Consume(nonce string) (bool, error)
}

type entry struct {
	expiresAt time.Time
}

// InMemoryNonceStore is the default NonceStore.
type InMemoryNonceStore struct {
	ttl     time.Duration
	mu      sync.Mutex
	entries map[string]entry

	// gcEvery controls how often expired nonces are garbage-collected during
	// Issue calls. 0 means GC on every issue.
	gcEvery int
	ops     int
}

// NewInMemoryNonceStore returns a new store. Pass 0 for ttl to use the default.
func NewInMemoryNonceStore(ttl time.Duration) *InMemoryNonceStore {
	if ttl <= 0 {
		ttl = DefaultNonceTTL
	}
	return &InMemoryNonceStore{
		ttl:     ttl,
		entries: make(map[string]entry),
		gcEvery: 64,
	}
}

// Issue implements NonceStore.
func (s *InMemoryNonceStore) Issue() (string, time.Time, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", time.Time{}, err
	}
	nonce := base64.RawURLEncoding.EncodeToString(buf[:])
	exp := time.Now().UTC().Add(s.ttl)

	s.mu.Lock()
	s.entries[nonce] = entry{expiresAt: exp}
	s.ops++
	if s.gcEvery == 0 || s.ops%s.gcEvery == 0 {
		s.gcLocked(time.Now().UTC())
	}
	s.mu.Unlock()

	return nonce, exp, nil
}

// Consume implements NonceStore using a constant-time equality check.
func (s *InMemoryNonceStore) Consume(nonce string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	// Scan with constant-time comparison to avoid leaking which nonces exist
	// via timing. The overhead is negligible given the store's small size.
	var found string
	for key := range s.entries {
		if subtle.ConstantTimeCompare([]byte(key), []byte(nonce)) == 1 {
			found = key
			break
		}
	}
	if found == "" {
		return false, nil
	}
	e := s.entries[found]
	delete(s.entries, found)
	if now.After(e.expiresAt) {
		return false, nil
	}
	return true, nil
}

// gcLocked removes expired entries. Caller must hold s.mu.
func (s *InMemoryNonceStore) gcLocked(now time.Time) {
	for k, v := range s.entries {
		if now.After(v.expiresAt) {
			delete(s.entries, k)
		}
	}
}
