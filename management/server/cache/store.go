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

const RedisStoreEnvVar = "NB_IDP_CACHE_REDIS_ADDRESS"

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

	redisClient := redis.NewClient(options)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = redisClient.Ping(ctx).Result()
	if err != nil {
		return nil, err
	}

	return redis_store.NewRedis(redisClient), nil
}
