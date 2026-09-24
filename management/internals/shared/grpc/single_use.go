package grpc

import (
	"context"
	"fmt"
	"time"

	"github.com/eko/gocache/lib/v4/store"
	log "github.com/sirupsen/logrus"

	nbcache "github.com/netbirdio/netbird/management/server/cache"
)

// SingleUseStore stores short-lived values that can be retrieved only once.
type SingleUseStore struct {
	cache nbcache.Store
	ctx   context.Context
}

// NewSingleUseStore creates a single-use value store over the shared cache.
func NewSingleUseStore(ctx context.Context, cacheStore nbcache.Store) *SingleUseStore {
	return &SingleUseStore{
		cache: cacheStore,
		ctx:   ctx,
	}
}

// Store saves value under key with the given TTL, after which it is evicted.
func (s *SingleUseStore) Store(key, value string, ttl time.Duration) error {
	if err := s.cache.Set(s.ctx, key, value, store.WithExpiration(ttl)); err != nil {
		return fmt.Errorf("store single-use value: %w", err)
	}
	return nil
}

// LoadAndDelete retrieves and removes the value for a key.
func (s *SingleUseStore) LoadAndDelete(key string) (string, bool) {
	value, found, err := s.cache.GetDel(s.ctx, key)
	if err != nil {
		log.Warnf("failed to consume single-use value: %v", err)
		return "", false
	}
	if !found {
		return "", false
	}
	return value, true
}
