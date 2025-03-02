package cache_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/eko/gocache/lib/v4/store"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"

	testcontainersredis "github.com/testcontainers/testcontainers-go/modules/redis"

	"github.com/netbirdio/netbird/management/server/cache"
)

func TestMemoryStore(t *testing.T) {
	memStore := cache.NewStore(100*time.Millisecond, 300*time.Millisecond)
	ctx := context.Background()
	key, value := "testing", "tested"
	err := memStore.Set(ctx, key, value)
	if err != nil {
		t.Errorf("couldn't set testing data: %s", err)
	}
	result, err := memStore.Get(ctx, key)
	if err != nil {
		t.Errorf("couldn't get testing data: %s", err)
	}
	if value != result.(string) {
		t.Errorf("value returned doesn't match testing data, got %s, expected %s", result, value)
	}
	// test expiration
	time.Sleep(300 * time.Millisecond)
	result, err = memStore.Get(ctx, key)
	if err == nil {
		t.Error("value should not be found")
	}
}

func TestRedisStoreConnectionFailure(t *testing.T) {
	t.Setenv(cache.RedisStoreEnvVar, "127.0.0.1:6379")
	redisStore := cache.NewStore(10*time.Millisecond, 30*time.Millisecond)
	ctx := context.Background()
	key, value := "testing", "tested"
	err := redisStore.Set(ctx, key, value)
	if err == nil {
		t.Error("it should fail to connect to redis to set a value")
	}
	result, err := redisStore.Get(ctx, key)
	if err == nil {
		t.Error("it should fail to connect to redis to get a value")
	}
	if value == result.(string) {
		t.Error("values shouldn't match because of lack of connection")
	}
}

func TestRedisStoreConnectionSuccess(t *testing.T) {
	ctx := context.Background()
	redisContainer, err := testcontainersredis.RunContainer(ctx, testcontainers.WithImage("redis:7"))
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

	u, err := url.Parse(redisURL)
	if err != nil {
		t.Fatalf("couldn't parse redis URL: %s", err)
	}
	addr := u.Hostname() + ":" + u.Port()

	t.Setenv(cache.RedisStoreEnvVar, addr)
	redisStore := cache.NewStore(100*time.Millisecond, 300*time.Millisecond)

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

	redisClient := redis.NewClient(&redis.Options{Addr: addr})
	r, e := redisClient.Get(ctx, key).Result()
	if e != nil {
		t.Errorf("couldn't get testing data from redis: %s", e)
	}
	if value != r {
		t.Errorf("value returned from redis doesn't match testing data, got %s, expected %s", r, value)
	}
	// test expiration
	time.Sleep(300 * time.Millisecond)
	result, err = redisStore.Get(ctx, key)
	if err == nil {
		t.Error("value should not be found")
	}
}
