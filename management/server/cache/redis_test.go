package cache_test

import (
	"context"
	"testing"
	"time"

	"github.com/eko/gocache/lib/v4/store"
	"github.com/redis/go-redis/v9"
	testcontainersredis "github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/netbirdio/netbird/management/server/cache"
)

func TestRedisStoreConnectionFailure(t *testing.T) {
	t.Setenv(cache.RedisStoreEnvVar, "redis://127.0.0.1:6379")
	_, err := cache.NewStore(context.Background(), 10*time.Millisecond, 30*time.Millisecond, 100)
	if err == nil {
		t.Fatal("getting redis cache store should return error")
	}
}

func TestRedisStoreConnectionSuccess(t *testing.T) {
	ctx := context.Background()
	redisContainer, err := testcontainersredis.Run(ctx, "redis:7")
	if err != nil {
		t.Fatalf("couldn't start redis container: %s", err)
	}
	defer func() {
		if err := redisContainer.Terminate(ctx); err != nil {
			t.Logf("failed to terminate container: %s", err)
		}
	}()
	redisURL, err := redisContainer.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("couldn't get connection string: %s", err)
	}

	t.Setenv(cache.RedisStoreEnvVar, redisURL)
	redisStore, err := cache.NewStore(context.Background(), 100*time.Millisecond, 300*time.Millisecond, 100)
	if err != nil {
		t.Fatalf("couldn't create redis store: %s", err)
	}

	key, value := "testing", "tested"
	err = redisStore.Set(ctx, key, value, store.WithExpiration(100*time.Millisecond))
	if err != nil {
		t.Errorf("couldn't set testing data: %s", err)
	}
	result, err := redisStore.Get(ctx, key)
	if err != nil {
		t.Errorf("couldn't get testing data: %s", err)
	}
	if value != result.(string) {
		t.Errorf("value returned doesn't match testing data, got %s, expected %s", result, value)
	}

	options, err := redis.ParseURL(redisURL)
	if err != nil {
		t.Errorf("parsing redis cache url: %s", err)
	}

	redisClient := redis.NewClient(options)
	r, e := redisClient.Get(ctx, key).Result()
	if e != nil {
		t.Errorf("couldn't get testing data from redis: %s", e)
	}
	if value != r {
		t.Errorf("value returned from redis doesn't match testing data, got %s, expected %s", r, value)
	}

	secondRedisStore, err := cache.NewStore(context.Background(), 100*time.Millisecond, 300*time.Millisecond, 100)
	if err != nil {
		t.Fatalf("couldn't create second redis store: %s", err)
	}
	start := make(chan struct{})
	type setResult struct {
		created bool
		err     error
	}
	results := make(chan setResult, 2)
	for _, cacheStore := range []cache.Store{redisStore, secondRedisStore} {
		go func() {
			<-start
			created, err := cacheStore.SetNX(ctx, "atomic", value, time.Second)
			results <- setResult{created: created, err: err}
		}()
	}
	close(start)

	created := 0
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatalf("atomic redis set failed: %s", result.err)
		}
		if result.created {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("expected exactly one redis client to create the entry, got %d", created)
	}
	ttl, err := redisClient.PTTL(ctx, "atomic").Result()
	if err != nil {
		t.Fatalf("couldn't read atomic entry TTL: %s", err)
	}
	if ttl <= 0 {
		t.Fatalf("atomic entry should have a positive TTL, got %s", ttl)
	}

	// test expiration
	time.Sleep(300 * time.Millisecond)
	_, err = redisStore.Get(ctx, key)
	if err == nil {
		t.Error("value should not be found")
	}
}
