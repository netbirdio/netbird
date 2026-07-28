package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	log "github.com/sirupsen/logrus"
)

// PKCEVerifierStore manages PKCE verifiers for OAuth flows.
// Supports both in-memory and Redis storage via NB_IDP_CACHE_REDIS_ADDRESS env var.
type PKCEVerifierStore struct {
	cache *cache.Cache[string]
	ctx   context.Context
}

// NewPKCEVerifierStore creates a PKCE verifier store using the provided shared cache store.
func NewPKCEVerifierStore(ctx context.Context, cacheStore store.StoreInterface) *PKCEVerifierStore {
	return &PKCEVerifierStore{
		cache: cache.New[string](cacheStore),
		ctx:   ctx,
	}
}

// Store saves a PKCE verifier associated with an OAuth state parameter.
// The verifier is stored with the specified TTL and will be automatically deleted after expiration.
func (s *PKCEVerifierStore) Store(state, verifier string, ttl time.Duration) error {
	if err := s.cache.Set(s.ctx, state, verifier, store.WithExpiration(ttl)); err != nil {
		return fmt.Errorf("failed to store PKCE verifier: %w", err)
	}

	log.Debugf("Stored PKCE verifier for state (expires in %s)", ttl)
	return nil
}

// LoadAndDelete retrieves and removes a PKCE verifier for the given state.
// Returns the verifier and true if found, or empty string and false if not found.
// This enforces single-use semantics for PKCE verifiers.
func (s *PKCEVerifierStore) LoadAndDelete(state string) (string, bool) {
	verifier, err := s.cache.Get(s.ctx, state)
	if err != nil {
		log.Debugf("PKCE verifier not found for state")
		return "", false
	}

	if err := s.cache.Delete(s.ctx, state); err != nil {
		log.Warnf("Failed to delete PKCE verifier for state: %v", err)
	}

	return verifier, true
}
