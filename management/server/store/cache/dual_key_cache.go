package cache

import (
	"context"
	"sync"
)

// DualKeyCache provides a caching mechanism where each entry has two keys:
// - Primary key (e.g., objectID): used for accessing and invalidating specific entries
// - Secondary key (e.g., accountID): used for bulk invalidation of all entries with the same secondary key
type DualKeyCache[K1 comparable, K2 comparable, V any] struct {
	mu             sync.RWMutex
	primaryIndex   map[K1]V               // Primary key -> Value
	secondaryIndex map[K2]map[K1]struct{} // Secondary key -> Set of primary keys
	reverseLookup  map[K1]K2              // Primary key -> Secondary key
}

// NewDualKeyCache creates a new dual-key cache
func NewDualKeyCache[K1 comparable, K2 comparable, V any]() *DualKeyCache[K1, K2, V] {
	return &DualKeyCache[K1, K2, V]{
		primaryIndex:   make(map[K1]V),
		secondaryIndex: make(map[K2]map[K1]struct{}),
		reverseLookup:  make(map[K1]K2),
	}
}

// Get retrieves a value from the cache using the primary key
func (c *DualKeyCache[K1, K2, V]) Get(ctx context.Context, primaryKey K1) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	value, ok := c.primaryIndex[primaryKey]
	return value, ok
}

// Set stores a value in the cache with both primary and secondary keys
func (c *DualKeyCache[K1, K2, V]) Set(ctx context.Context, primaryKey K1, secondaryKey K2, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if oldSecondaryKey, exists := c.reverseLookup[primaryKey]; exists {
		if primaryKeys, ok := c.secondaryIndex[oldSecondaryKey]; ok {
			delete(primaryKeys, primaryKey)
			if len(primaryKeys) == 0 {
				delete(c.secondaryIndex, oldSecondaryKey)
			}
		}
	}

	c.primaryIndex[primaryKey] = value
	c.reverseLookup[primaryKey] = secondaryKey

	if _, exists := c.secondaryIndex[secondaryKey]; !exists {
		c.secondaryIndex[secondaryKey] = make(map[K1]struct{})
	}
	c.secondaryIndex[secondaryKey][primaryKey] = struct{}{}
}

// InvalidateByPrimaryKey removes an entry using the primary key
func (c *DualKeyCache[K1, K2, V]) InvalidateByPrimaryKey(ctx context.Context, primaryKey K1) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if secondaryKey, exists := c.reverseLookup[primaryKey]; exists {
		if primaryKeys, ok := c.secondaryIndex[secondaryKey]; ok {
			delete(primaryKeys, primaryKey)
			if len(primaryKeys) == 0 {
				delete(c.secondaryIndex, secondaryKey)
			}
		}
		delete(c.reverseLookup, primaryKey)
	}

	delete(c.primaryIndex, primaryKey)
}

// InvalidateBySecondaryKey removes all entries with the given secondary key
func (c *DualKeyCache[K1, K2, V]) InvalidateBySecondaryKey(ctx context.Context, secondaryKey K2) {
	c.mu.Lock()
	defer c.mu.Unlock()

	primaryKeys, exists := c.secondaryIndex[secondaryKey]
	if !exists {
		return
	}

	for primaryKey := range primaryKeys {
		delete(c.primaryIndex, primaryKey)
		delete(c.reverseLookup, primaryKey)
	}

	delete(c.secondaryIndex, secondaryKey)
}

// InvalidateAll removes all entries from the cache
func (c *DualKeyCache[K1, K2, V]) InvalidateAll(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.primaryIndex = make(map[K1]V)
	c.secondaryIndex = make(map[K2]map[K1]struct{})
	c.reverseLookup = make(map[K1]K2)
}

// Size returns the number of entries in the cache
func (c *DualKeyCache[K1, K2, V]) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.primaryIndex)
}

// GetOrSet retrieves a value from the cache, or sets it using the provided function if not found
// The loadFunc should return both the value and the secondary key (extracted from the value)
func (c *DualKeyCache[K1, K2, V]) GetOrSet(ctx context.Context, primaryKey K1, loadFunc func() (V, K2, error)) (V, error) {
	if value, ok := c.Get(ctx, primaryKey); ok {
		return value, nil
	}

	value, secondaryKey, err := loadFunc()
	if err != nil {
		var zero V
		return zero, err
	}

	c.Set(ctx, primaryKey, secondaryKey, value)

	return value, nil
}
