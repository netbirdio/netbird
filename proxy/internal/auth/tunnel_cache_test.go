package auth

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

func newTestKey(account types.AccountID, ip string, domain string) tunnelCacheKey {
	return tunnelCacheKey{
		accountID: account,
		tunnelIP:  netip.MustParseAddr(ip),
		domain:    domain,
	}
}

func TestTunnelCache_HitSkipsRPC(t *testing.T) {
	cache := newTunnelValidationCache()
	key := newTestKey("acct-1", "100.64.0.10", "svc.example")

	var calls int32
	validate := func(_ context.Context, req *proto.ValidateTunnelPeerRequest) (*proto.ValidateTunnelPeerResponse, error) {
		atomic.AddInt32(&calls, 1)
		return &proto.ValidateTunnelPeerResponse{Valid: true, SessionToken: "tok", UserId: "user-1"}, nil
	}

	resp, fromCache, err := cache.fetch(context.Background(), key, validate)
	require.NoError(t, err)
	require.NotNil(t, resp, "first fetch returns RPC response")
	assert.False(t, fromCache, "first fetch must not be cached")

	resp2, fromCache2, err := cache.fetch(context.Background(), key, validate)
	require.NoError(t, err)
	require.NotNil(t, resp2, "second fetch returns cached response")
	assert.True(t, fromCache2, "second fetch must be served from cache")
	assert.Equal(t, "user-1", resp2.GetUserId(), "cached response should preserve user identity")
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "validate should run exactly once with one cache hit")
}

func TestTunnelCache_ExpiredEntryRefetches(t *testing.T) {
	cache := newTunnelValidationCache()
	clock := time.Now()
	cache.now = func() time.Time { return clock }

	key := newTestKey("acct-1", "100.64.0.10", "svc.example")
	var calls int32
	validate := func(_ context.Context, _ *proto.ValidateTunnelPeerRequest) (*proto.ValidateTunnelPeerResponse, error) {
		atomic.AddInt32(&calls, 1)
		return &proto.ValidateTunnelPeerResponse{Valid: true, SessionToken: "tok"}, nil
	}

	_, _, err := cache.fetch(context.Background(), key, validate)
	require.NoError(t, err)
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "first fetch issues one RPC")

	clock = clock.Add(tunnelCacheTTL + time.Second)

	_, fromCache, err := cache.fetch(context.Background(), key, validate)
	require.NoError(t, err)
	assert.False(t, fromCache, "expired entry must miss the cache")
	assert.Equal(t, int32(2), atomic.LoadInt32(&calls), "expired entry forces a re-fetch")
}

func TestTunnelCache_DeniedResponseNotCached(t *testing.T) {
	cache := newTunnelValidationCache()
	key := newTestKey("acct-1", "100.64.0.10", "svc.example")

	var calls int32
	validate := func(_ context.Context, _ *proto.ValidateTunnelPeerRequest) (*proto.ValidateTunnelPeerResponse, error) {
		atomic.AddInt32(&calls, 1)
		return &proto.ValidateTunnelPeerResponse{Valid: false, DeniedReason: "not_in_group"}, nil
	}

	for i := 0; i < 3; i++ {
		_, _, err := cache.fetch(context.Background(), key, validate)
		require.NoError(t, err, "fetch must not error on denied response")
	}
	assert.Equal(t, int32(3), atomic.LoadInt32(&calls), "denied responses bypass the cache so policy changes apply immediately")
}

func TestTunnelCache_ConcurrentColdHitsCoalesce(t *testing.T) {
	cache := newTunnelValidationCache()
	key := newTestKey("acct-1", "100.64.0.10", "svc.example")

	gate := make(chan struct{})
	var calls int32
	validate := func(_ context.Context, _ *proto.ValidateTunnelPeerRequest) (*proto.ValidateTunnelPeerResponse, error) {
		atomic.AddInt32(&calls, 1)
		<-gate
		return &proto.ValidateTunnelPeerResponse{Valid: true, SessionToken: "tok"}, nil
	}

	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers)
	results := make([]bool, workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			resp, _, err := cache.fetch(context.Background(), key, validate)
			results[idx] = err == nil && resp.GetValid()
		}(i)
	}

	time.Sleep(20 * time.Millisecond)
	close(gate)
	wg.Wait()

	for i, ok := range results {
		assert.Truef(t, ok, "worker %d should observe a successful response", i)
	}
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls), "single-flight must collapse concurrent cold fetches into one RPC")
}

func TestTunnelCache_PerAccountIsolation(t *testing.T) {
	cache := newTunnelValidationCache()
	keyA := newTestKey("acct-a", "100.64.0.10", "svc.example")
	keyB := newTestKey("acct-b", "100.64.0.10", "svc.example")

	var callsA, callsB int32
	validateA := func(_ context.Context, _ *proto.ValidateTunnelPeerRequest) (*proto.ValidateTunnelPeerResponse, error) {
		atomic.AddInt32(&callsA, 1)
		return &proto.ValidateTunnelPeerResponse{Valid: true, SessionToken: "tok-a", UserId: "user-a"}, nil
	}
	validateB := func(_ context.Context, _ *proto.ValidateTunnelPeerRequest) (*proto.ValidateTunnelPeerResponse, error) {
		atomic.AddInt32(&callsB, 1)
		return &proto.ValidateTunnelPeerResponse{Valid: true, SessionToken: "tok-b", UserId: "user-b"}, nil
	}

	respA, _, err := cache.fetch(context.Background(), keyA, validateA)
	require.NoError(t, err)
	respB, _, err := cache.fetch(context.Background(), keyB, validateB)
	require.NoError(t, err)

	assert.Equal(t, "user-a", respA.GetUserId(), "account A response should belong to user-a")
	assert.Equal(t, "user-b", respB.GetUserId(), "account B response must not be served from account A's cache")
	assert.Equal(t, int32(1), atomic.LoadInt32(&callsA), "validateA called exactly once")
	assert.Equal(t, int32(1), atomic.LoadInt32(&callsB), "validateB called exactly once")
}

func TestTunnelCache_BoundedSizeEvictsOldest(t *testing.T) {
	cache := newTunnelValidationCache()
	cache.maxSize = 2

	validate := func(_ context.Context, req *proto.ValidateTunnelPeerRequest) (*proto.ValidateTunnelPeerResponse, error) {
		return &proto.ValidateTunnelPeerResponse{Valid: true, SessionToken: "tok-" + req.GetTunnelIp()}, nil
	}

	keys := []tunnelCacheKey{
		newTestKey("acct-1", "100.64.0.10", "svc"),
		newTestKey("acct-1", "100.64.0.11", "svc"),
		newTestKey("acct-1", "100.64.0.12", "svc"),
	}
	for _, k := range keys {
		_, _, err := cache.fetch(context.Background(), k, validate)
		require.NoError(t, err)
	}

	assert.Nil(t, cache.get(keys[0]), "oldest key should be evicted past maxSize")
	assert.NotNil(t, cache.get(keys[1]), "second-newest must remain cached")
	assert.NotNil(t, cache.get(keys[2]), "newest must remain cached")
}
