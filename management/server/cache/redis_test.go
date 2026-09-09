package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/eko/gocache/lib/v4/store"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	testcontainersredis "github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/netbirdio/netbird/management/server/cache"
)

func startRedis(t *testing.T) string {
	t.Helper()

	ctx := context.Background()
	redisContainer, err := testcontainersredis.Run(ctx, "redis:7")
	require.NoError(t, err, "couldn't start redis container")

	t.Cleanup(func() {
		if err := redisContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %s", err)
		}
	})

	redisURL, err := redisContainer.ConnectionString(ctx)
	require.NoError(t, err, "couldn't get connection string")

	t.Setenv(cache.RedisStoreEnvVar, redisURL)
	return redisURL
}

func newRedisStore(t *testing.T) cache.Store {
	t.Helper()

	redisStore, err := cache.NewStore(context.Background(), 100*time.Millisecond, 300*time.Millisecond, 100)
	require.NoError(t, err)

	return redisStore
}

func TestRedisStoreConnectionFailure(t *testing.T) {
	t.Setenv(cache.RedisStoreEnvVar, "redis://127.0.0.1:6379")
	_, err := cache.NewStore(context.Background(), 10*time.Millisecond, 30*time.Millisecond, 100)
	require.Error(t, err, "getting redis cache store should return error")
}

func TestRedisStoreConnectionSuccess(t *testing.T) {
	ctx := context.Background()
	redisURL := startRedis(t)
	redisStore := newRedisStore(t)

	key, value := "testing", "tested"
	err := redisStore.Set(ctx, key, value, store.WithExpiration(100*time.Millisecond))
	assert.NoError(t, err, "couldn't set testing data")

	result, err := redisStore.Get(ctx, key)
	assert.NoError(t, err, "couldn't get testing data")
	assert.Equal(t, value, result, "value returned doesn't match testing data")

	options, err := redis.ParseURL(redisURL)
	require.NoError(t, err, "parsing redis cache url")

	redisClient := redis.NewClient(options)
	r, err := redisClient.Get(ctx, key).Result()
	assert.NoError(t, err, "couldn't get testing data from redis")
	assert.Equal(t, value, r, "value returned from redis doesn't match testing data")

	// test expiration
	time.Sleep(300 * time.Millisecond)
	_, err = redisStore.Get(ctx, key)
	assert.Error(t, err, "value should not be found")
}

func TestRedisStoreSetNX(t *testing.T) {
	ctx := context.Background()
	redisURL := startRedis(t)
	redisStore, secondRedisStore := newRedisStore(t), newRedisStore(t)

	const (
		key   = "conditional"
		value = "tested"
	)

	start := make(chan struct{})
	type setResult struct {
		created bool
		err     error
	}
	results := make(chan setResult, 2)
	for _, cacheStore := range []cache.Store{redisStore, secondRedisStore} {
		go func() {
			<-start
			created, err := cacheStore.SetNX(ctx, key, value, time.Minute)
			results <- setResult{created: created, err: err}
		}()
	}
	close(start)

	created := 0
	for range 2 {
		result := <-results
		require.NoError(t, result.err, "conditional redis set failed")
		if result.created {
			created++
		}
	}
	require.Equal(t, 1, created, "expected exactly one redis client to create the entry")

	options, err := redis.ParseURL(redisURL)
	require.NoError(t, err, "parsing redis cache url")

	ttl, err := redis.NewClient(options).PTTL(ctx, key).Result()
	require.NoError(t, err, "couldn't read entry TTL")
	require.Positive(t, ttl, "created entry should have a positive TTL")
}

func TestRedisStoreGetDel(t *testing.T) {
	ctx := context.Background()
	startRedis(t)
	redisStore, secondRedisStore := newRedisStore(t), newRedisStore(t)

	const (
		key   = "consume"
		value = "verifier"
	)

	t.Run("exactly one caller across independent clients consumes the key", func(t *testing.T) {
		// A generous TTL: the key is consumed explicitly, so expiry racing the
		// concurrent callers would only make the test flaky on a loaded runner.
		err := redisStore.Set(ctx, key, value, store.WithExpiration(time.Minute))
		require.NoError(t, err, "couldn't set value to consume")

		assertGetDelConsumedOnce(ctx, t, []cache.Store{redisStore, secondRedisStore}, key, value)
		assertGetDelMisses(ctx, t, secondRedisStore, key)
	})

	t.Run("missing key is not an error", func(t *testing.T) {
		assertGetDelMisses(ctx, t, redisStore, "never-set")
	})

	t.Run("expired key is not found", func(t *testing.T) {
		err := redisStore.Set(ctx, key, value, store.WithExpiration(50*time.Millisecond))
		require.NoError(t, err, "couldn't set value to consume")

		time.Sleep(100 * time.Millisecond)
		assertGetDelMisses(ctx, t, redisStore, key)
	})
}
