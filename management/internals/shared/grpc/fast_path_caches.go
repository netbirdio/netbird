package grpc

import (
	"context"
	"encoding/json"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	log "github.com/sirupsen/logrus"

	nbtypes "github.com/netbirdio/netbird/management/server/types"
)

const (
	extraSettingsCacheKeyPrefix = "extra-settings:"
	peerGroupsCacheKeyPrefix    = "peer-groups:"

	// DefaultExtraSettingsCacheTTL bounds how long a cached ExtraSettings
	// blob survives. Settings rarely change; a ~30s window is cheap and
	// bounded by the fact that a change also rotates through recordPeerSync
	// writes (which don't affect this cache, but client reconnects do).
	DefaultExtraSettingsCacheTTL = 30 * time.Second

	// DefaultPeerGroupsCacheTTL bounds how long a cached peer group set
	// survives. Shorter than ExtraSettings because group membership changes
	// have user-visible authz implications.
	DefaultPeerGroupsCacheTTL = 15 * time.Second
)

// extraSettingsCache caches the ExtraSettings JSON per account so the fast
// path's buildFastPathResponse can skip GetExtraSettings on cache hit.
// TTL-based; staleness window is ~DefaultExtraSettingsCacheTTL.
type extraSettingsCache struct {
	cache *cache.Cache[string]
	ctx   context.Context
	ttl   time.Duration
}

func newExtraSettingsCache(ctx context.Context, cacheStore store.StoreInterface, ttl time.Duration) *extraSettingsCache {
	if cacheStore == nil {
		return nil
	}
	return &extraSettingsCache{cache: cache.New[string](cacheStore), ctx: ctx, ttl: ttl}
}

func (c *extraSettingsCache) get(accountID string) (*nbtypes.ExtraSettings, bool) {
	if c == nil {
		return nil, false
	}
	raw, err := c.cache.Get(c.ctx, extraSettingsCacheKeyPrefix+accountID)
	if err != nil {
		return nil, false
	}
	var es nbtypes.ExtraSettings
	if err := json.Unmarshal([]byte(raw), &es); err != nil {
		log.Debugf("extra settings cache: unmarshal for %s: %v", accountID, err)
		return nil, false
	}
	return &es, true
}

func (c *extraSettingsCache) set(accountID string, es *nbtypes.ExtraSettings) {
	if c == nil || es == nil {
		return
	}
	payload, err := json.Marshal(es)
	if err != nil {
		log.Debugf("extra settings cache: marshal for %s: %v", accountID, err)
		return
	}
	if err := c.cache.Set(c.ctx, extraSettingsCacheKeyPrefix+accountID, string(payload), store.WithExpiration(c.ttl)); err != nil {
		log.Debugf("extra settings cache: set for %s: %v", accountID, err)
	}
}

// peerGroupsCache caches the list of group IDs a peer belongs to so the fast
// path's buildFastPathResponse can skip GetPeerGroupIDs on cache hit. The
// cache key includes the peerID; group membership changes propagate via TTL.
type peerGroupsCache struct {
	cache *cache.Cache[string]
	ctx   context.Context
	ttl   time.Duration
}

func newPeerGroupsCache(ctx context.Context, cacheStore store.StoreInterface, ttl time.Duration) *peerGroupsCache {
	if cacheStore == nil {
		return nil
	}
	return &peerGroupsCache{cache: cache.New[string](cacheStore), ctx: ctx, ttl: ttl}
}

func (c *peerGroupsCache) get(peerID string) ([]string, bool) {
	if c == nil {
		return nil, false
	}
	raw, err := c.cache.Get(c.ctx, peerGroupsCacheKeyPrefix+peerID)
	if err != nil {
		return nil, false
	}
	var ids []string
	if err := json.Unmarshal([]byte(raw), &ids); err != nil {
		log.Debugf("peer groups cache: unmarshal for %s: %v", peerID, err)
		return nil, false
	}
	return ids, true
}

func (c *peerGroupsCache) set(peerID string, ids []string) {
	if c == nil {
		return
	}
	payload, err := json.Marshal(ids)
	if err != nil {
		log.Debugf("peer groups cache: marshal for %s: %v", peerID, err)
		return
	}
	if err := c.cache.Set(c.ctx, peerGroupsCacheKeyPrefix+peerID, string(payload), store.WithExpiration(c.ttl)); err != nil {
		log.Debugf("peer groups cache: set for %s: %v", peerID, err)
	}
}
