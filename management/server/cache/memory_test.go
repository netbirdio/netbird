package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/cache"
)

func TestMemoryStore(t *testing.T) {
	memStore, err := cache.NewStore(context.Background(), 100*time.Millisecond, 300*time.Millisecond, 100)
	require.NoError(t, err, "couldn't create memory store")

	ctx := context.Background()
	key, value := "testing", "tested"
	err = memStore.Set(ctx, key, value)
	assert.NoError(t, err, "couldn't set testing data")

	result, err := memStore.Get(ctx, key)
	assert.NoError(t, err, "couldn't get testing data")
	assert.Equal(t, value, result, "value returned doesn't match testing data")

	created, err := memStore.SetNX(ctx, "conditional", value, 100*time.Millisecond)
	require.NoError(t, err, "couldn't conditionally set testing data")
	require.True(t, created, "first conditional set should create the entry")

	created, err = memStore.SetNX(ctx, "conditional", value, 100*time.Millisecond)
	require.NoError(t, err, "couldn't conditionally check testing data")
	require.False(t, created, "second conditional set should not replace the entry")

	// test expiration
	time.Sleep(300 * time.Millisecond)
	_, err = memStore.Get(ctx, key)
	assert.Error(t, err, "value should not be found")
}

func TestMemoryStoreGetDel(t *testing.T) {
	ctx := context.Background()
	newStore := func(t *testing.T) cache.Store {
		t.Helper()
		memStore, err := cache.NewStore(ctx, time.Minute, time.Minute, 100)
		require.NoError(t, err, "couldn't create memory store")

		return memStore
	}

	const (
		key   = "consume"
		value = "verifier"
	)

	t.Run("exactly one concurrent caller consumes the key", func(t *testing.T) {
		memStore := newStore(t)
		require.NoError(t, memStore.Set(ctx, key, value), "couldn't set testing data")

		assertGetDelConsumedOnce(ctx, t, []cache.Store{memStore}, key, value)
		assertGetDelMisses(ctx, t, memStore, key)
	})

	t.Run("missing key is not an error", func(t *testing.T) {
		assertGetDelMisses(ctx, t, newStore(t), "never-set")
	})

	t.Run("expired key is not found", func(t *testing.T) {
		memStore := newStore(t)
		_, err := memStore.SetNX(ctx, key, value, 50*time.Millisecond)
		require.NoError(t, err, "couldn't set testing data")

		time.Sleep(100 * time.Millisecond)
		assertGetDelMisses(ctx, t, memStore, key)
	})
}
