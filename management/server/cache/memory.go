package cache

import (
	"context"
	"time"

	"github.com/eko/gocache/lib/v4/store"
	gocachestore "github.com/eko/gocache/store/go_cache/v4"
	gocache "github.com/patrickmn/go-cache"
)

type goCacheStore struct {
	store.StoreInterface
	client *gocache.Cache
}

func newMemoryStore(maxTimeout, cleanupInterval time.Duration) Store {
	client := gocache.New(maxTimeout, cleanupInterval)
	return &goCacheStore{
		StoreInterface: gocachestore.NewGoCache(client),
		client:         client,
	}
}

func (s *goCacheStore) SetNX(_ context.Context, key, value string, ttl time.Duration) (bool, error) {
	// Add only returns an error when a non-expired entry already exists.
	if err := s.client.Add(key, value, ttl); err != nil {
		return false, nil
	}
	return true, nil
}
