package cache

import (
	"context"
	"sync"
)

// SingleKeyCache provides a simple caching mechanism with a single key
type SingleKeyCache[K comparable, V any] struct {
	mu    sync.RWMutex
	cache map[K]V // Key -> Value
}

// NewSingleKeyCache creates a new single-key cache
func NewSingleKeyCache[K comparable, V any]() *SingleKeyCache[K, V] {
	return &SingleKeyCache[K, V]{
		cache: make(map[K]V),
	}
}

// Get retrieves a value from the cache using the key
func (c *SingleKeyCache[K, V]) Get(ctx context.Context, key K) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	value, ok := c.cache[key]
	return value, ok
}

// Set stores a value in the cache with the given key
func (c *SingleKeyCache[K, V]) Set(ctx context.Context, key K, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache[key] = value
}

// Invalidate removes an entry using the key
func (c *SingleKeyCache[K, V]) Invalidate(ctx context.Context, key K) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.cache, key)
}

// InvalidateAll removes all entries from the cache
func (c *SingleKeyCache[K, V]) InvalidateAll(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[K]V)
}

// Size returns the number of entries in the cache
func (c *SingleKeyCache[K, V]) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.cache)
}

// GetOrSet retrieves a value from the cache, or sets it using the provided function if not found
func (c *SingleKeyCache[K, V]) GetOrSet(ctx context.Context, key K, loadFunc func() (V, error)) (V, error) {
	if value, ok := c.Get(ctx, key); ok {
		return value, nil
	}

	value, err := loadFunc()
	if err != nil {
		var zero V
		return zero, err
	}

	c.Set(ctx, key, value)

	return value, nil
}
