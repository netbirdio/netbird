package cache

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/eko/gocache/lib/v4/store"
	redisstore "github.com/eko/gocache/store/redis/v4"
	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

type redisStore struct {
	store.StoreInterface
	client *redis.Client
}

func getRedisStore(ctx context.Context, redisEnvAddr string, maxConn int) (Store, error) {
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

	return &redisStore{
		StoreInterface: redisstore.NewRedis(redisClient),
		client:         redisClient,
	}, nil
}

func (s *redisStore) SetNX(ctx context.Context, key, value string, ttl time.Duration) (bool, error) {
	return s.client.SetNX(ctx, key, value, ttl).Result()
}
