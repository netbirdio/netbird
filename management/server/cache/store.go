package cache

import (
	"os"
	"time"

	"github.com/eko/gocache/lib/v4/store"
	gocache_store "github.com/eko/gocache/store/go_cache/v4"
	redis_store "github.com/eko/gocache/store/redis/v4"
	gocache "github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"
)

const RedisStoreEnvVar = "NB_IDP_CACHE_REDIS_ADDRESS"

func NewStore(maxTimeout, cleanupInterval time.Duration) store.StoreInterface {
	if os.Getenv(RedisStoreEnvVar) != "" {
		addr := os.Getenv(RedisStoreEnvVar)
		redisClient := redis.NewClient(&redis.Options{Addr: addr})
		return redis_store.NewRedis(redisClient)
	}
	goc := gocache.New(maxTimeout, cleanupInterval)
	return gocache_store.NewGoCache(goc)
}
