package auth

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// tunnelCacheTTL caps how long a positive ValidateTunnelPeer result is
// reused before re-fetching from management. 5 minutes balances freshness
// against management load on busy mesh networks.
const tunnelCacheTTL = 300 * time.Second

// tunnelCachePerAccount caps the number of cached identities per account.
// Bounded eviction avoids memory growth in pathological cases (huge peer
// roster, brief request bursts) while staying generous for normal use.
const tunnelCachePerAccount = 1024

// tunnelCacheKey identifies a cached entry by tunnel IP and originating
// account. Domain is part of the value, not the key, because the
// management response is per (account, IP) — domain only gates whether a
// re-fetch is needed if the operator is accessing a different service.
type tunnelCacheKey struct {
	accountID types.AccountID
	tunnelIP  netip.Addr
	domain    string
}

// tunnelCacheEntry stores a positive validation response with the time it
// was minted. Entries past tunnelCacheTTL are treated as misses.
type tunnelCacheEntry struct {
	resp     *proto.ValidateTunnelPeerResponse
	cachedAt time.Time
}

// tunnelValidationCache memoizes ValidateTunnelPeer responses keyed by
// (accountID, tunnelIP, domain). Only successful, valid responses are
// cached — denials skip the cache so policy changes apply immediately.
// Single-flight de-duplicates concurrent fetches for the same key so a
// burst of cold requests collapses into a single RPC.
type tunnelValidationCache struct {
	mu      sync.Mutex
	entries map[types.AccountID]*accountBucket
	flight  singleflight.Group
	ttl     time.Duration
	maxSize int
	now     func() time.Time
}

// accountBucket holds the cached entries for a single account, with a
// FIFO eviction queue used when the bucket exceeds maxSize.
type accountBucket struct {
	items map[tunnelCacheKey]tunnelCacheEntry
	order []tunnelCacheKey
}

// newTunnelValidationCache constructs a cache with default TTL and bounds.
func newTunnelValidationCache() *tunnelValidationCache {
	return &tunnelValidationCache{
		entries: make(map[types.AccountID]*accountBucket),
		ttl:     tunnelCacheTTL,
		maxSize: tunnelCachePerAccount,
		now:     time.Now,
	}
}

// get returns a cached response for the key, or nil when missing or
// expired. Expired entries are evicted lazily on read.
func (c *tunnelValidationCache) get(key tunnelCacheKey) *proto.ValidateTunnelPeerResponse {
	c.mu.Lock()
	defer c.mu.Unlock()

	bucket, ok := c.entries[key.accountID]
	if !ok {
		return nil
	}
	entry, ok := bucket.items[key]
	if !ok {
		return nil
	}
	if c.now().Sub(entry.cachedAt) > c.ttl {
		delete(bucket.items, key)
		bucket.order = removeKey(bucket.order, key)
		return nil
	}
	return entry.resp
}

// put records a positive response under the key. Evicts the oldest entry
// in the account's bucket when the bound is exceeded.
func (c *tunnelValidationCache) put(key tunnelCacheKey, resp *proto.ValidateTunnelPeerResponse) {
	c.mu.Lock()
	defer c.mu.Unlock()

	bucket, ok := c.entries[key.accountID]
	if !ok {
		bucket = &accountBucket{items: make(map[tunnelCacheKey]tunnelCacheEntry)}
		c.entries[key.accountID] = bucket
	}
	if _, exists := bucket.items[key]; !exists {
		bucket.order = append(bucket.order, key)
	}
	bucket.items[key] = tunnelCacheEntry{resp: resp, cachedAt: c.now()}

	for len(bucket.order) > c.maxSize {
		oldest := bucket.order[0]
		bucket.order = bucket.order[1:]
		delete(bucket.items, oldest)
	}
}

// removeKey drops the first occurrence of needle from order. The cache
// uses small slices so a linear scan is cheaper than a map+slice combo.
func removeKey(order []tunnelCacheKey, needle tunnelCacheKey) []tunnelCacheKey {
	for i, k := range order {
		if k == needle {
			return append(order[:i], order[i+1:]...)
		}
	}
	return order
}

// flightKey turns a cache key into a single-flight string. AccountID and
// IP isolation by themselves are insufficient because different domains
// for the same peer/account may have different group access.
func flightKey(key tunnelCacheKey) string {
	return string(key.accountID) + "|" + key.tunnelIP.String() + "|" + key.domain
}

// validateTunnelPeerFn is the RPC entry point the cache wraps. It matches
// the SessionValidator.ValidateTunnelPeer signature without exposing the
// gRPC option variadic, since callers don't need it on the cache hot path.
type validateTunnelPeerFn func(ctx context.Context, req *proto.ValidateTunnelPeerRequest) (*proto.ValidateTunnelPeerResponse, error)

// fetch returns a cached response when present, otherwise calls validate
// under single-flight and caches the result. Denied responses pass
// through but are not cached so policy changes apply immediately.
func (c *tunnelValidationCache) fetch(ctx context.Context, key tunnelCacheKey, validate validateTunnelPeerFn) (*proto.ValidateTunnelPeerResponse, bool, error) {
	if resp := c.get(key); resp != nil {
		return resp, true, nil
	}

	flight := flightKey(key)
	res, err, _ := c.flight.Do(flight, func() (any, error) {
		if cached := c.get(key); cached != nil {
			return cached, nil
		}
		resp, err := validate(ctx, &proto.ValidateTunnelPeerRequest{
			TunnelIp: key.tunnelIP.String(),
			Domain:   key.domain,
		})
		if err != nil {
			return nil, err
		}
		if resp.GetValid() && resp.GetSessionToken() != "" {
			c.put(key, resp)
		}
		return resp, nil
	})
	if err != nil {
		return nil, false, err
	}
	resp, _ := res.(*proto.ValidateTunnelPeerResponse)
	return resp, false, nil
}
