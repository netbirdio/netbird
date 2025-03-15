package cache

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/eko/gocache/lib/v4/store"
	gocache_store "github.com/eko/gocache/store/go_cache/v4"
	redis_store "github.com/eko/gocache/store/redis/v4"
	gocache "github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"
)

// RedisStoreEnvVar is the environment variable that determines if a redis store should be used.
// The value should follow redis URL format. https://github.com/redis/redis-specifications/blob/master/uri/redis.txt
const RedisStoreEnvVar = "NB_IDP_CACHE_REDIS_ADDRESS"

// NewStore creates a new cache store with the given max timeout and cleanup interval. It checks for the environment Variable RedisStoreEnvVar
// to determine if a redis store should be used. If the environment variable is set, it will attempt to connect to the redis store.
func NewStore(maxTimeout, cleanupInterval time.Duration) (store.StoreInterface, error) {
	redisAddr := os.Getenv(RedisStoreEnvVar)
	if redisAddr != "" {
		return getRedisStore(redisAddr)
	}
	goc := gocache.New(maxTimeout, cleanupInterval)
	return gocache_store.NewGoCache(goc), nil
}

func getRedisStore(redisEnvAddr string) (store.StoreInterface, error) {
	options, err := redis.ParseURL(redisEnvAddr)
	if err != nil {
		return nil, fmt.Errorf("parsing redis cache url: %s", err)
	}

	options.MaxIdleConns = 6
	options.MinIdleConns = 3
	options.MaxActiveConns = 100
	redisClient := redis.NewClient(options)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = redisClient.Ping(ctx).Result()
	if err != nil {
		return nil, err
	}

	return redis_store.NewRedis(redisClient), nil
}
