package configurer

import (
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const statsCacheTTL = 1 * time.Second

type statsCache struct {
	ttl   time.Duration
	fetch func() (map[string]WGStats, error)

	mu       sync.RWMutex
	value    map[string]WGStats
	expireAt time.Time

	sf singleflight.Group
}

func newStatsCache(ttl time.Duration, fetch func() (map[string]WGStats, error)) *statsCache {
	return &statsCache{ttl: ttl, fetch: fetch}
}

func (c *statsCache) get() (map[string]WGStats, error) {
	c.mu.RLock()
	if c.value != nil && time.Now().Before(c.expireAt) {
		value := c.value
		c.mu.RUnlock()
		return value, nil
	}
	c.mu.RUnlock()

	value, err, _ := c.sf.Do("stats", func() (interface{}, error) {
		res, err := c.fetch()
		if err != nil {
			return nil, err
		}

		c.mu.Lock()
		c.value = res
		c.expireAt = time.Now().Add(c.ttl)
		c.mu.Unlock()
		return res, nil
	})
	if err != nil {
		return nil, err
	}
	return value.(map[string]WGStats), nil
}
