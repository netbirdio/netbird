package cache

import (
	"context"
	"sync"
)

// TripleKeyCache provides a caching mechanism where each entry has three keys:
// - Primary key (K1): used for accessing and invalidating specific entries
// - Secondary key (K2): used for bulk invalidation of all entries with the same secondary key
// - Tertiary key (K3): used for bulk invalidation of all entries with the same tertiary key
type TripleKeyCache[K1 comparable, K2 comparable, K3 comparable, V any] struct {
	mu             sync.RWMutex
	primaryIndex   map[K1]V               // Primary key -> Value
	secondaryIndex map[K2]map[K1]struct{} // Secondary key -> Set of primary keys
	tertiaryIndex  map[K3]map[K1]struct{} // Tertiary key -> Set of primary keys
	reverseLookup  map[K1]keyPair[K2, K3] // Primary key -> Secondary and Tertiary keys
}

type keyPair[K2 comparable, K3 comparable] struct {
	secondary K2
	tertiary  K3
}

// NewTripleKeyCache creates a new triple-key cache
func NewTripleKeyCache[K1 comparable, K2 comparable, K3 comparable, V any]() *TripleKeyCache[K1, K2, K3, V] {
	return &TripleKeyCache[K1, K2, K3, V]{
		primaryIndex:   make(map[K1]V),
		secondaryIndex: make(map[K2]map[K1]struct{}),
		tertiaryIndex:  make(map[K3]map[K1]struct{}),
		reverseLookup:  make(map[K1]keyPair[K2, K3]),
	}
}

// Get retrieves a value from the cache using the primary key
func (c *TripleKeyCache[K1, K2, K3, V]) Get(ctx context.Context, primaryKey K1) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	value, ok := c.primaryIndex[primaryKey]
	return value, ok
}

// Set stores a value in the cache with primary, secondary, and tertiary keys
func (c *TripleKeyCache[K1, K2, K3, V]) Set(ctx context.Context, primaryKey K1, secondaryKey K2, tertiaryKey K3, value V) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if oldKeys, exists := c.reverseLookup[primaryKey]; exists {
		if primaryKeys, ok := c.secondaryIndex[oldKeys.secondary]; ok {
			delete(primaryKeys, primaryKey)
			if len(primaryKeys) == 0 {
				delete(c.secondaryIndex, oldKeys.secondary)
			}
		}
		if primaryKeys, ok := c.tertiaryIndex[oldKeys.tertiary]; ok {
			delete(primaryKeys, primaryKey)
			if len(primaryKeys) == 0 {
				delete(c.tertiaryIndex, oldKeys.tertiary)
			}
		}
	}

	c.primaryIndex[primaryKey] = value
	c.reverseLookup[primaryKey] = keyPair[K2, K3]{
		secondary: secondaryKey,
		tertiary:  tertiaryKey,
	}

	if _, exists := c.secondaryIndex[secondaryKey]; !exists {
		c.secondaryIndex[secondaryKey] = make(map[K1]struct{})
	}
	c.secondaryIndex[secondaryKey][primaryKey] = struct{}{}

	if _, exists := c.tertiaryIndex[tertiaryKey]; !exists {
		c.tertiaryIndex[tertiaryKey] = make(map[K1]struct{})
	}
	c.tertiaryIndex[tertiaryKey][primaryKey] = struct{}{}
}

// InvalidateByPrimaryKey removes an entry using the primary key
func (c *TripleKeyCache[K1, K2, K3, V]) InvalidateByPrimaryKey(ctx context.Context, primaryKey K1) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if keys, exists := c.reverseLookup[primaryKey]; exists {
		if primaryKeys, ok := c.secondaryIndex[keys.secondary]; ok {
			delete(primaryKeys, primaryKey)
			if len(primaryKeys) == 0 {
				delete(c.secondaryIndex, keys.secondary)
			}
		}
		if primaryKeys, ok := c.tertiaryIndex[keys.tertiary]; ok {
			delete(primaryKeys, primaryKey)
			if len(primaryKeys) == 0 {
				delete(c.tertiaryIndex, keys.tertiary)
			}
		}
		delete(c.reverseLookup, primaryKey)
	}

	delete(c.primaryIndex, primaryKey)
}

// InvalidateBySecondaryKey removes all entries with the given secondary key
func (c *TripleKeyCache[K1, K2, K3, V]) InvalidateBySecondaryKey(ctx context.Context, secondaryKey K2) {
	c.mu.Lock()
	defer c.mu.Unlock()

	primaryKeys, exists := c.secondaryIndex[secondaryKey]
	if !exists {
		return
	}

	for primaryKey := range primaryKeys {
		if keys, ok := c.reverseLookup[primaryKey]; ok {
			if tertiaryPrimaryKeys, exists := c.tertiaryIndex[keys.tertiary]; exists {
				delete(tertiaryPrimaryKeys, primaryKey)
				if len(tertiaryPrimaryKeys) == 0 {
					delete(c.tertiaryIndex, keys.tertiary)
				}
			}
		}
		delete(c.primaryIndex, primaryKey)
		delete(c.reverseLookup, primaryKey)
	}

	delete(c.secondaryIndex, secondaryKey)
}

// InvalidateByTertiaryKey removes all entries with the given tertiary key
func (c *TripleKeyCache[K1, K2, K3, V]) InvalidateByTertiaryKey(ctx context.Context, tertiaryKey K3) {
	c.mu.Lock()
	defer c.mu.Unlock()

	primaryKeys, exists := c.tertiaryIndex[tertiaryKey]
	if !exists {
		return
	}

	for primaryKey := range primaryKeys {
		if keys, ok := c.reverseLookup[primaryKey]; ok {
			if secondaryPrimaryKeys, exists := c.secondaryIndex[keys.secondary]; exists {
				delete(secondaryPrimaryKeys, primaryKey)
				if len(secondaryPrimaryKeys) == 0 {
					delete(c.secondaryIndex, keys.secondary)
				}
			}
		}
		delete(c.primaryIndex, primaryKey)
		delete(c.reverseLookup, primaryKey)
	}

	delete(c.tertiaryIndex, tertiaryKey)
}

// InvalidateAll removes all entries from the cache
func (c *TripleKeyCache[K1, K2, K3, V]) InvalidateAll(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.primaryIndex = make(map[K1]V)
	c.secondaryIndex = make(map[K2]map[K1]struct{})
	c.tertiaryIndex = make(map[K3]map[K1]struct{})
	c.reverseLookup = make(map[K1]keyPair[K2, K3])
}

// Size returns the number of entries in the cache
func (c *TripleKeyCache[K1, K2, K3, V]) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return len(c.primaryIndex)
}

// GetOrSet retrieves a value from the cache, or sets it using the provided function if not found
// The loadFunc should return the value, secondary key, and tertiary key (extracted from the value)
func (c *TripleKeyCache[K1, K2, K3, V]) GetOrSet(ctx context.Context, primaryKey K1, loadFunc func() (V, K2, K3, error)) (V, error) {
	if value, ok := c.Get(ctx, primaryKey); ok {
		return value, nil
	}

	value, secondaryKey, tertiaryKey, err := loadFunc()
	if err != nil {
		var zero V
		return zero, err
	}

	c.Set(ctx, primaryKey, secondaryKey, tertiaryKey, value)

	return value, nil
}

// GetOrSetBySecondaryKey retrieves a value from the cache using the secondary key, or sets it using the provided function if not found
// The loadFunc should return the value, primary key, secondary key, and tertiary key
func (c *TripleKeyCache[K1, K2, K3, V]) GetOrSetBySecondaryKey(ctx context.Context, secondaryKey K2, loadFunc func() (V, K1, K3, error)) (V, error) {
	c.mu.RLock()
	if primaryKeys, exists := c.secondaryIndex[secondaryKey]; exists && len(primaryKeys) > 0 {
		for primaryKey := range primaryKeys {
			if value, ok := c.primaryIndex[primaryKey]; ok {
				c.mu.RUnlock()
				return value, nil
			}
		}
	}
	c.mu.RUnlock()

	value, primaryKey, tertiaryKey, err := loadFunc()
	if err != nil {
		var zero V
		return zero, err
	}

	c.Set(ctx, primaryKey, secondaryKey, tertiaryKey, value)

	return value, nil
}

// GetOrSetByTertiaryKey retrieves a value from the cache using the tertiary key, or sets it using the provided function if not found
// The loadFunc should return the value, primary key, secondary key, and tertiary key
func (c *TripleKeyCache[K1, K2, K3, V]) GetOrSetByTertiaryKey(ctx context.Context, tertiaryKey K3, loadFunc func() (V, K1, K2, error)) (V, error) {
	c.mu.RLock()
	if primaryKeys, exists := c.tertiaryIndex[tertiaryKey]; exists && len(primaryKeys) > 0 {
		for primaryKey := range primaryKeys {
			if value, ok := c.primaryIndex[primaryKey]; ok {
				c.mu.RUnlock()
				return value, nil
			}
		}
	}
	c.mu.RUnlock()

	value, primaryKey, secondaryKey, err := loadFunc()
	if err != nil {
		var zero V
		return zero, err
	}

	c.Set(ctx, primaryKey, secondaryKey, tertiaryKey, value)

	return value, nil
}
