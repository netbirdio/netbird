package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
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
		return fmt.Errorf("store used token entry: %w", err)
	}
	if !created {
		return ErrTokenAlreadyUsed
	}

	return nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(canonicalizeToken(token)))
	return hex.EncodeToString(sum[:])
}

// canonicalizeToken re-encodes the JWT signature segment so noncanonical
// spellings of the same signature map to one stable cache key.
func canonicalizeToken(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return token
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return token
	}

	return parts[0] + "." + parts[1] + "." + base64.RawURLEncoding.EncodeToString(sig)
}
