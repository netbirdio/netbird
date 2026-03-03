package grpc

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// OneTimeTokenStore manages short-lived, single-use authentication tokens
// for proxy-to-management RPC authentication. Tokens are generated when
// a service is created and must be used exactly once by the proxy
// to authenticate a subsequent RPC call.
type OneTimeTokenStore struct {
	tokens      map[string]*tokenMetadata
	mu          sync.RWMutex
	cleanup     *time.Ticker
	cleanupDone chan struct{}
}

// tokenMetadata stores information about a one-time token
type tokenMetadata struct {
	ServiceID string
	AccountID string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// NewOneTimeTokenStore creates a new token store with automatic cleanup
// of expired tokens. The cleanupInterval determines how often expired
// tokens are removed from memory.
func NewOneTimeTokenStore(cleanupInterval time.Duration) *OneTimeTokenStore {
	store := &OneTimeTokenStore{
		tokens:      make(map[string]*tokenMetadata),
		cleanup:     time.NewTicker(cleanupInterval),
		cleanupDone: make(chan struct{}),
	}

	// Start background cleanup goroutine
	go store.cleanupExpired()

	return store
}

// GenerateToken creates a new cryptographically secure one-time token
// with the specified TTL. The token is associated with a specific
// accountID and serviceID for validation purposes.
//
// Returns the generated token string or an error if random generation fails.
func (s *OneTimeTokenStore) GenerateToken(accountID, serviceID string, ttl time.Duration) (string, error) {
	// Generate 32 bytes (256 bits) of cryptographically secure random data
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}

	// Encode as URL-safe base64 for easy transmission in gRPC
	token := base64.URLEncoding.EncodeToString(randomBytes)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[token] = &tokenMetadata{
		ServiceID: serviceID,
		AccountID: accountID,
		ExpiresAt: time.Now().Add(ttl),
		CreatedAt: time.Now(),
	}

	log.Debugf("Generated one-time token for proxy %s in account %s (expires in %s)",
		serviceID, accountID, ttl)

	return token, nil
}

// ValidateAndConsume verifies the token against the provided accountID and
// serviceID, checks expiration, and then deletes it to enforce single-use.
//
// This method uses constant-time comparison to prevent timing attacks.
//
// Returns nil on success, or an error if:
// - Token doesn't exist
// - Token has expired
// - Account ID doesn't match
// - Reverse proxy ID doesn't match
func (s *OneTimeTokenStore) ValidateAndConsume(token, accountID, serviceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	metadata, exists := s.tokens[token]
	if !exists {
		log.Warnf("Token validation failed: token not found (proxy: %s, account: %s)",
			serviceID, accountID)
		return fmt.Errorf("invalid token")
	}

	// Check expiration
	if time.Now().After(metadata.ExpiresAt) {
		delete(s.tokens, token)
		log.Warnf("Token validation failed: token expired (proxy: %s, account: %s)",
			serviceID, accountID)
		return fmt.Errorf("token expired")
	}

	// Validate account ID using constant-time comparison (prevents timing attacks)
	if subtle.ConstantTimeCompare([]byte(metadata.AccountID), []byte(accountID)) != 1 {
		log.Warnf("Token validation failed: account ID mismatch (expected: %s, got: %s)",
			metadata.AccountID, accountID)
		return fmt.Errorf("account ID mismatch")
	}

	// Validate service ID using constant-time comparison
	if subtle.ConstantTimeCompare([]byte(metadata.ServiceID), []byte(serviceID)) != 1 {
		log.Warnf("Token validation failed: service ID mismatch (expected: %s, got: %s)",
			metadata.ServiceID, serviceID)
		return fmt.Errorf("service ID mismatch")
	}

	// Delete token immediately to enforce single-use
	delete(s.tokens, token)

	log.Infof("Token validated and consumed for proxy %s in account %s",
		serviceID, accountID)

	return nil
}

// cleanupExpired removes expired tokens in the background to prevent memory leaks
func (s *OneTimeTokenStore) cleanupExpired() {
	for {
		select {
		case <-s.cleanup.C:
			s.mu.Lock()
			now := time.Now()
			removed := 0
			for token, metadata := range s.tokens {
				if now.After(metadata.ExpiresAt) {
					delete(s.tokens, token)
					removed++
				}
			}
			if removed > 0 {
				log.Debugf("Cleaned up %d expired one-time tokens", removed)
			}
			s.mu.Unlock()
		case <-s.cleanupDone:
			return
		}
	}
}

// Close stops the cleanup goroutine and releases resources
func (s *OneTimeTokenStore) Close() {
	s.cleanup.Stop()
	close(s.cleanupDone)
}

// GetTokenCount returns the current number of tokens in the store (for debugging/metrics)
func (s *OneTimeTokenStore) GetTokenCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tokens)
}
