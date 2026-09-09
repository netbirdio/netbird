package cache

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/eko/gocache/lib/v4/store"
	gocachestore "github.com/eko/gocache/store/go_cache/v4"
	gocache "github.com/patrickmn/go-cache"
)

type goCacheStore struct {
	store.StoreInterface
	client *gocache.Cache
	mu     sync.Mutex
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
		return false, nil //nolint:nilerr
	}
	return true, nil
}

// GetDel reads the value under key and removes it. go-cache has no native read-and-delete
// and releases its own lock between the two calls, so mu holds the pair together and no
// value is consumed twice.
//
// Writes do not take mu: a Set landing mid-pair is lost, since GetDel returns the prior
// value and deletes the new one. Callers must write a consumed key only once.
func (s *goCacheStore) GetDel(_ context.Context, key string) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	value, found := s.client.Get(key)
	if !found {
		return "", false, nil
	}
	s.client.Delete(key)

	str, ok := value.(string)
	if !ok {
		return "", false, fmt.Errorf("cached value is %T, not a string", value)
	}
	return str, true, nil
}
