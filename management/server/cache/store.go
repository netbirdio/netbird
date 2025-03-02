package cache

import (
	"os"
	"time"

	"github.com/eko/gocache/v3/store"
	cacheStore "github.com/eko/gocache/v3/store"
	"github.com/go-redis/redis/v8"
	gocache "github.com/patrickmn/go-cache"
)

func NewStore(maxTimeout, cleanupInterval time.Duration) store.StoreInterface {
	if os.Getenv("NB_IDP_CACHE_REDIS_ADDRESS") != "" {
		addr := os.Getenv("NB_IDP_CACHE_REDIS_ADDRESS")
		redisClient := redis.NewClient(&redis.Options{Addr: addr})
		return cacheStore.NewRedis(redisClient)
	}
	goc := gocache.New(maxTimeout, cleanupInterval)
	return cacheStore.NewGoCache(goc)
}
