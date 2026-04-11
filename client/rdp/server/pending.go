package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

const (
	// DefaultSessionTTL is the default time-to-live for pending RDP sessions.
	DefaultSessionTTL = 60 * time.Second

	// cleanupInterval is how often the store checks for expired sessions.
	cleanupInterval = 10 * time.Second

	// nonceLength is the length of the nonce in bytes.
	nonceLength = 32
)

// PendingRDPSession represents an authorized but not yet consumed RDP session.
type PendingRDPSession struct {
	SessionID  string
	PeerIP     netip.Addr
	OSUsername string
	Domain     string
	JWTUserID  string // for audit trail
	Nonce      string // replay protection
	CreatedAt  time.Time
	ExpiresAt  time.Time
	consumed   bool
}

// PendingStore manages pending RDP session entries with automatic expiration.
type PendingStore struct {
	mu       sync.RWMutex
	sessions map[string]*PendingRDPSession // keyed by SessionID
	nonces   map[string]struct{}           // seen nonces for replay protection
	ttl      time.Duration
}

// NewPendingStore creates a new pending session store with the given TTL.
func NewPendingStore(ttl time.Duration) *PendingStore {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	return &PendingStore{
		sessions: make(map[string]*PendingRDPSession),
		nonces:   make(map[string]struct{}),
		ttl:      ttl,
	}
}

// Add creates a new pending RDP session and returns it.
func (ps *PendingStore) Add(peerIP netip.Addr, osUsername, domain, jwtUserID, nonce string) (*PendingRDPSession, error) {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	// Check nonce for replay protection
	if _, seen := ps.nonces[nonce]; seen {
		return nil, fmt.Errorf("duplicate nonce: replay detected")
	}
	ps.nonces[nonce] = struct{}{}

	now := time.Now()
	session := &PendingRDPSession{
		SessionID:  uuid.New().String(),
		PeerIP:     peerIP,
		OSUsername: osUsername,
		Domain:     domain,
		JWTUserID:  jwtUserID,
		Nonce:      nonce,
		CreatedAt:  now,
		ExpiresAt:  now.Add(ps.ttl),
	}

	ps.sessions[session.SessionID] = session

	log.Debugf("RDP pending session created: id=%s peer=%s user=%s domain=%s expires=%s",
		session.SessionID, peerIP, osUsername, domain, session.ExpiresAt.Format(time.RFC3339))

	return session, nil
}

// QueryByPeerIP finds the first non-consumed, non-expired pending session for the given peer IP.
func (ps *PendingStore) QueryByPeerIP(peerIP netip.Addr) (*PendingRDPSession, bool) {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	now := time.Now()
	for _, session := range ps.sessions {
		if session.PeerIP == peerIP && !session.consumed && now.Before(session.ExpiresAt) {
			return session, true
		}
	}
	return nil, false
}

// Consume marks a session as consumed (single-use). Returns true if the session
// was found and successfully consumed, false if it was already consumed, expired, or not found.
func (ps *PendingStore) Consume(sessionID string) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	session, exists := ps.sessions[sessionID]
	if !exists {
		return false
	}

	if session.consumed {
		log.Debugf("RDP pending session already consumed: id=%s", sessionID)
		return false
	}

	if time.Now().After(session.ExpiresAt) {
		log.Debugf("RDP pending session expired: id=%s", sessionID)
		return false
	}

	session.consumed = true
	log.Debugf("RDP pending session consumed: id=%s peer=%s user=%s",
		sessionID, session.PeerIP, session.OSUsername)
	return true
}

// StartCleanup runs a background goroutine that periodically removes expired sessions.
func (ps *PendingStore) StartCleanup(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				ps.cleanup()
			}
		}
	}()
}

// cleanup removes expired and consumed sessions.
func (ps *PendingStore) cleanup() {
	ps.mu.Lock()
	defer ps.mu.Unlock()

	now := time.Now()
	for id, session := range ps.sessions {
		if now.After(session.ExpiresAt) || session.consumed {
			delete(ps.sessions, id)
			delete(ps.nonces, session.Nonce)
		}
	}
}

// Count returns the number of active (non-expired, non-consumed) sessions.
func (ps *PendingStore) Count() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()

	count := 0
	now := time.Now()
	for _, session := range ps.sessions {
		if !session.consumed && now.Before(session.ExpiresAt) {
			count++
		}
	}
	return count
}

// GenerateNonce creates a cryptographically random nonce for replay protection.
func GenerateNonce() (string, error) {
	b := make([]byte, nonceLength)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}
