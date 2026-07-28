package cache

import (
	"context"
	"fmt"
	"math"
	"os"
	"time"

	"github.com/eko/gocache/lib/v4/store"
	gocache_store "github.com/eko/gocache/store/go_cache/v4"
	redis_store "github.com/eko/gocache/store/redis/v4"
	gocache "github.com/patrickmn/go-cache"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

// RedisStoreEnvVar is the environment variable that determines if a redis store should be used.
// The value should follow redis URL format. https://github.com/redis/redis-specifications/blob/master/uri/redis.txt
const RedisStoreEnvVar = "NB_CACHE_REDIS_ADDRESS"

// legacyIdPCacheRedisEnvVar is the previous environment variable used for IDP cache.
const legacyIdPCacheRedisEnvVar = "NB_IDP_CACHE_REDIS_ADDRESS"

const (
	// DefaultStoreMaxTimeout is the default max timeout for the shared cache store.
	DefaultStoreMaxTimeout = 7 * 24 * time.Hour
	// DefaultStoreCleanupInterval is the default cleanup interval for the shared cache store.
	DefaultStoreCleanupInterval = 30 * time.Minute
	// DefaultStoreMaxConn is the default max connections for the shared cache store.
	DefaultStoreMaxConn = 1000
)

// NewStore creates a new cache store with the given max timeout and cleanup interval. It checks for the environment Variable RedisStoreEnvVar
// to determine if a redis store should be used. If the environment variable is set, it will attempt to connect to the redis store.
func NewStore(ctx context.Context, maxTimeout, cleanupInterval time.Duration, maxConn int) (store.StoreInterface, error) {
	redisAddr := GetAddrFromEnv()
	if redisAddr != "" {
		return getRedisStore(ctx, redisAddr, maxConn)
	}
	goc := gocache.New(maxTimeout, cleanupInterval)
	return gocache_store.NewGoCache(goc), nil
}

// GetAddrFromEnv returns the redis address from the environment variable RedisStoreEnvVar or its legacy counterpart.
func GetAddrFromEnv() string {
	addr := os.Getenv(RedisStoreEnvVar)
	if addr == "" {
		addr = os.Getenv(legacyIdPCacheRedisEnvVar)
	}
	return addr
}

func getRedisStore(ctx context.Context, redisEnvAddr string, maxConn int) (store.StoreInterface, error) {
	options, err := redis.ParseURL(redisEnvAddr)
	if err != nil {
		return nil, fmt.Errorf("parsing redis cache url: %s", err)
	}

	options.MaxIdleConns = int(math.Ceil(float64(maxConn) * 0.5)) // 50% of max conns
	options.MinIdleConns = int(math.Ceil(float64(maxConn) * 0.1)) // 10% of max conns
	options.MaxActiveConns = maxConn
	options.ConnMaxIdleTime = 30 * time.Minute
	options.ConnMaxLifetime = 0
	options.PoolTimeout = 10 * time.Second
	redisClient := redis.NewClient(options)
	subCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	_, err = redisClient.Ping(subCtx).Result()
	if err != nil {
		return nil, err
	}

	log.WithContext(subCtx).Infof("using redis cache at %s", redisEnvAddr)

	return redis_store.NewRedis(redisClient), nil
}
