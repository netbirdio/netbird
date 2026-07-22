package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

const (
	usedTokenKeyPrefix = "jwt-used:"
	usedTokenMarker    = "1"
)

var (
	ErrTokenAlreadyUsed = errors.New("JWT already used")
	ErrTokenExpired     = errors.New("JWT expired")
)

// TokenCache atomically records used JWTs until their expiration.
type TokenCache interface {
	SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
}

type SessionStore struct {
	cache TokenCache
}

func NewSessionStore(cacheStore TokenCache) *SessionStore {
	return &SessionStore{cache: cacheStore}
}

// RegisterToken records a JWT until its exp time and rejects reuse.
func (s *SessionStore) RegisterToken(ctx context.Context, token string, expiresAt time.Time) error {
	ttl := time.Until(expiresAt)
	if ttl <= 0 {
		return ErrTokenExpired
	}

	key := usedTokenKeyPrefix + hashToken(token)
	created, err := s.cache.SetNX(ctx, key, usedTokenMarker, ttl)
	if err != nil {
		return fmt.Errorf("failed to store used token entry: %w", err)
	}
	if !created {
		return ErrTokenAlreadyUsed
	}

	return nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
