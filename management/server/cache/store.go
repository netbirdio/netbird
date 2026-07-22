package cache

import (
	"context"
	"os"
	"time"

	"github.com/eko/gocache/lib/v4/store"
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

// Store extends the shared cache interface with atomic insertion support.
type Store interface {
	store.StoreInterface
	// SetNX atomically stores a value with a TTL only when the key does not exist.
	SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error)
}

// NewStore creates a new cache store with the given max timeout and cleanup interval. It checks for the environment Variable RedisStoreEnvVar
// to determine if a redis store should be used. If the environment variable is set, it will attempt to connect to the redis store.
func NewStore(ctx context.Context, maxTimeout, cleanupInterval time.Duration, maxConn int) (Store, error) {
	redisAddr := GetAddrFromEnv()
	if redisAddr != "" {
		return getRedisStore(ctx, redisAddr, maxConn)
	}
	return newMemoryStore(maxTimeout, cleanupInterval), nil
}

// GetAddrFromEnv returns the redis address from the environment variable RedisStoreEnvVar or its legacy counterpart.
func GetAddrFromEnv() string {
	addr := os.Getenv(RedisStoreEnvVar)
	if addr == "" {
		addr = os.Getenv(legacyIdPCacheRedisEnvVar)
	}
	return addr
}
