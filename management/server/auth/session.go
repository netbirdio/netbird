package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
)

const (
	usedTokenKeyPrefix = "jwt-used:"
	usedTokenMarker    = "1"
)

var (
	ErrTokenAlreadyUsed = errors.New("JWT already used")
	ErrTokenExpired     = errors.New("JWT expired")
)

type SessionStore struct {
	cache *cache.Cache[string]
}

func NewSessionStore(cacheStore store.StoreInterface) *SessionStore {
	return &SessionStore{cache: cache.New[string](cacheStore)}
}

// RegisterToken records a JWT until its exp time and rejects reuse.
func (s *SessionStore) RegisterToken(ctx context.Context, token string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return ErrTokenExpired
	}

	key := usedTokenKeyPrefix + hashToken(token)
	_, err := s.cache.Get(ctx, key)
	if err == nil {
		return ErrTokenAlreadyUsed
	}

	var notFound *store.NotFound
	if !errors.As(err, &notFound) {
		return fmt.Errorf("failed to lookup used token entry: %w", err)
	}

	if err := s.cache.Set(ctx, key, usedTokenMarker, store.WithExpiration(ttl)); err != nil {
		return fmt.Errorf("failed to store used token entry: %w", err)
	}

	return nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
