package grpc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	log "github.com/sirupsen/logrus"
)

type tokenMetadata struct {
	ServiceID string
	AccountID string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// OneTimeTokenStore manages single-use authentication tokens for proxy-to-management RPC.
// Supports both in-memory and Redis storage via NB_IDP_CACHE_REDIS_ADDRESS env var.
type OneTimeTokenStore struct {
	cache *cache.Cache[string]
	ctx   context.Context
}

// NewOneTimeTokenStore creates a token store using the provided shared cache store.
func NewOneTimeTokenStore(ctx context.Context, cacheStore store.StoreInterface) *OneTimeTokenStore {
	return &OneTimeTokenStore{
		cache: cache.New[string](cacheStore),
		ctx:   ctx,
	}
}

// GenerateToken creates a new cryptographically secure one-time token
// with the specified TTL. The token is associated with a specific
// accountID and serviceID for validation purposes.
//
// Returns the generated token string or an error if random generation fails.
func (s *OneTimeTokenStore) GenerateToken(accountID, serviceID string, ttl time.Duration) (string, error) {
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}

	token := base64.URLEncoding.EncodeToString(randomBytes)
	hashedToken := hashToken(token)

	metadata := &tokenMetadata{
		ServiceID: serviceID,
		AccountID: accountID,
		ExpiresAt: time.Now().Add(ttl),
		CreatedAt: time.Now(),
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return "", fmt.Errorf("failed to serialize token metadata: %w", err)
	}

	if err := s.cache.Set(s.ctx, hashedToken, string(metadataJSON), store.WithExpiration(ttl)); err != nil {
		return "", fmt.Errorf("failed to store token: %w", err)
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
	hashedToken := hashToken(token)

	metadataJSON, err := s.cache.Get(s.ctx, hashedToken)
	if err != nil {
		log.Warnf("Token validation failed: token not found (proxy: %s, account: %s)", serviceID, accountID)
		return fmt.Errorf("invalid token")
	}

	metadata := &tokenMetadata{}
	if err := json.Unmarshal([]byte(metadataJSON), metadata); err != nil {
		log.Warnf("Token validation failed: failed to unmarshal metadata (proxy: %s, account: %s): %v", serviceID, accountID, err)
		return fmt.Errorf("invalid token metadata")
	}

	if time.Now().After(metadata.ExpiresAt) {
		log.Warnf("Token validation failed: token expired (proxy: %s, account: %s)", serviceID, accountID)
		return fmt.Errorf("token expired")
	}

	if subtle.ConstantTimeCompare([]byte(metadata.AccountID), []byte(accountID)) != 1 {
		log.Warnf("Token validation failed: account ID mismatch (expected: %s, got: %s)", metadata.AccountID, accountID)
		return fmt.Errorf("account ID mismatch")
	}

	if subtle.ConstantTimeCompare([]byte(metadata.ServiceID), []byte(serviceID)) != 1 {
		log.Warnf("Token validation failed: service ID mismatch (expected: %s, got: %s)", metadata.ServiceID, serviceID)
		return fmt.Errorf("service ID mismatch")
	}

	if err := s.cache.Delete(s.ctx, hashedToken); err != nil {
		log.Warnf("Token deletion warning (proxy: %s, account: %s): %v", serviceID, accountID, err)
	}

	log.Infof("Token validated and consumed for proxy %s in account %s", serviceID, accountID)

	return nil
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
