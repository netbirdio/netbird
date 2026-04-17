package grpc

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbcache "github.com/netbirdio/netbird/management/server/cache"
)

func newTestPeerSerialCache(t *testing.T, ttl, cleanup time.Duration) *PeerSerialCache {
	t.Helper()
	s, err := nbcache.NewStore(context.Background(), ttl, cleanup, 100)
	require.NoError(t, err, "cache store must initialise")
	return NewPeerSerialCache(context.Background(), s, ttl)
}

func TestPeerSerialCache_GetSetDelete(t *testing.T) {
	c := newTestPeerSerialCache(t, time.Minute, time.Minute)
	key := "pubkey-aaa"

	_, hit := c.Get(key)
	assert.False(t, hit, "empty cache must miss")

	c.Set(key, peerSyncEntry{Serial: 42, MetaHash: 7})

	entry, hit := c.Get(key)
	require.True(t, hit, "after Set, Get must hit")
	assert.Equal(t, uint64(42), entry.Serial, "serial roundtrip")
	assert.Equal(t, uint64(7), entry.MetaHash, "meta hash roundtrip")

	c.Delete(key)
	_, hit = c.Get(key)
	assert.False(t, hit, "after Delete, Get must miss")
}

func TestPeerSerialCache_GetMissReturnsZero(t *testing.T) {
	c := newTestPeerSerialCache(t, time.Minute, time.Minute)

	entry, hit := c.Get("missing")
	assert.False(t, hit, "miss must report false")
	assert.Equal(t, peerSyncEntry{}, entry, "miss must return zero value")
}

func TestPeerSerialCache_TTLExpiry(t *testing.T) {
	c := newTestPeerSerialCache(t, 100*time.Millisecond, 10*time.Millisecond)
	key := "pubkey-ttl"

	c.Set(key, peerSyncEntry{Serial: 1, MetaHash: 1})
	time.Sleep(250 * time.Millisecond)

	_, hit := c.Get(key)
	assert.False(t, hit, "entry must expire after TTL")
}

func TestPeerSerialCache_OverwriteUpdatesValue(t *testing.T) {
	c := newTestPeerSerialCache(t, time.Minute, time.Minute)
	key := "pubkey-overwrite"

	c.Set(key, peerSyncEntry{Serial: 1, MetaHash: 1})
	c.Set(key, peerSyncEntry{Serial: 99, MetaHash: 123})

	entry, hit := c.Get(key)
	require.True(t, hit, "overwritten key must still be present")
	assert.Equal(t, uint64(99), entry.Serial, "overwrite updates serial")
	assert.Equal(t, uint64(123), entry.MetaHash, "overwrite updates meta hash")
}

func TestPeerSerialCache_IsolatedPerKey(t *testing.T) {
	c := newTestPeerSerialCache(t, time.Minute, time.Minute)

	c.Set("a", peerSyncEntry{Serial: 1, MetaHash: 1})
	c.Set("b", peerSyncEntry{Serial: 2, MetaHash: 2})

	a, hitA := c.Get("a")
	b, hitB := c.Get("b")
	require.True(t, hitA, "key a must hit")
	require.True(t, hitB, "key b must hit")
	assert.Equal(t, uint64(1), a.Serial, "key a serial")
	assert.Equal(t, uint64(2), b.Serial, "key b serial")

	c.Delete("a")
	_, hitA = c.Get("a")
	_, hitB = c.Get("b")
	assert.False(t, hitA, "deleting a must not affect b")
	assert.True(t, hitB, "b must remain after a delete")
}

func TestPeerSerialCache_Concurrent(t *testing.T) {
	c := newTestPeerSerialCache(t, time.Minute, time.Minute)

	var wg sync.WaitGroup
	const workers = 50
	const iterations = 20

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			key := "pubkey"
			for i := 0; i < iterations; i++ {
				c.Set(key, peerSyncEntry{Serial: uint64(id*iterations + i), MetaHash: uint64(id)})
				_, _ = c.Get(key)
			}
		}(w)
	}

	wg.Wait()

	_, hit := c.Get("pubkey")
	assert.True(t, hit, "cache must survive concurrent Set/Get without deadlock")
}

func TestPeerSerialCache_Redis(t *testing.T) {
	if os.Getenv(nbcache.RedisStoreEnvVar) == "" {
		t.Skipf("set %s to run this test against a real Redis", nbcache.RedisStoreEnvVar)
	}

	s, err := nbcache.NewStore(context.Background(), time.Minute, 10*time.Second, 10)
	require.NoError(t, err, "redis store must initialise")
	c := NewPeerSerialCache(context.Background(), s, time.Minute)

	key := "redis-pubkey"
	c.Set(key, peerSyncEntry{Serial: 42, MetaHash: 7})
	entry, hit := c.Get(key)
	require.True(t, hit, "redis hit expected")
	assert.Equal(t, uint64(42), entry.Serial)
	c.Delete(key)
}
