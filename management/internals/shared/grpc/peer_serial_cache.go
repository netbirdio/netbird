package grpc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	log "github.com/sirupsen/logrus"
)

const (
	peerSerialCacheKeyPrefix = "peer-sync:"

	// DefaultPeerSerialCacheTTL bounds how long a cached serial survives. If the
	// cache write on a full-map send ever drops, entries naturally expire and
	// the next Sync falls back to the full path, re-priming the cache.
	DefaultPeerSerialCacheTTL = 24 * time.Hour
)

// PeerSerialCache records the NetworkMap serial and meta hash last delivered to
// each peer on Sync. Lookups are used to skip full network map computation when
// the peer already has the latest state. Backed by the shared cache store so
// entries survive management replicas sharing a Redis instance.
type PeerSerialCache struct {
	cache *cache.Cache[string]
	ctx   context.Context
	ttl   time.Duration
}

// NewPeerSerialCache creates a cache wrapper bound to the shared cache store.
// The ttl is applied to every Set call; entries older than ttl are treated as
// misses so the server eventually converges to delivering a full map even if
// an earlier Set was lost.
func NewPeerSerialCache(ctx context.Context, cacheStore store.StoreInterface, ttl time.Duration) *PeerSerialCache {
	return &PeerSerialCache{
		cache: cache.New[string](cacheStore),
		ctx:   ctx,
		ttl:   ttl,
	}
}

// Get returns the entry previously recorded for this peer and whether a valid
// entry was found. A cache miss or any read error is reported as a miss so
// callers fall back to the full map path.
func (c *PeerSerialCache) Get(pubKey string) (peerSyncEntry, bool) {
	raw, err := c.cache.Get(c.ctx, peerSerialCacheKeyPrefix+pubKey)
	if err != nil {
		return peerSyncEntry{}, false
	}

	entry := peerSyncEntry{}
	if err := json.Unmarshal([]byte(raw), &entry); err != nil {
		log.Debugf("peer serial cache: unmarshal entry for %s: %v", pubKey, err)
		return peerSyncEntry{}, false
	}
	return entry, true
}

// Set records what the server most recently delivered to this peer. Errors are
// logged at debug level so cache outages degrade gracefully into the full map
// path on the next Sync rather than failing the current Sync.
func (c *PeerSerialCache) Set(pubKey string, entry peerSyncEntry) {
	payload, err := json.Marshal(entry)
	if err != nil {
		log.Debugf("peer serial cache: marshal entry for %s: %v", pubKey, err)
		return
	}

	if err := c.cache.Set(c.ctx, peerSerialCacheKeyPrefix+pubKey, string(payload), store.WithExpiration(c.ttl)); err != nil {
		log.Debugf("peer serial cache: set entry for %s: %v", pubKey, err)
	}
}

// Delete removes any cached entry for this peer. Used on Login so the next
// Sync always sees a miss and delivers a full map.
func (c *PeerSerialCache) Delete(pubKey string) {
	if err := c.cache.Delete(c.ctx, peerSerialCacheKeyPrefix+pubKey); err != nil {
		log.Debugf("peer serial cache: delete entry for %s: %v", pubKey, err)
	}
}

// cacheKey exposes the namespaced key for tests that need to peek at the raw
// storage, e.g. when asserting TTL behaviour against Redis.
func (c *PeerSerialCache) cacheKey(pubKey string) string {
	return fmt.Sprintf("%s%s", peerSerialCacheKeyPrefix, pubKey)
}
