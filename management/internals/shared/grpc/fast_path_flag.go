package grpc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

const (
	fastPathRedisURLEnv = "NB_PEER_SYNC_REDIS_ADDRESS"

	// DefaultFastPathFlagInterval is the default poll interval for the Sync
	// fast-path feature flag. Kept lower than the log-level overrider because
	// operators will want the toggle to propagate quickly during rollout.
	DefaultFastPathFlagInterval = 1 * time.Minute

	// DefaultFastPathRedisKey is the Redis key polled by RunFastPathFlagRoutine
	// when the caller does not provide an override.
	DefaultFastPathRedisKey = "peerSyncFastPath"
)

// FastPathFlag exposes the current on/off state of the Sync fast path. The
// zero value and a nil receiver both report disabled, so callers can always
// treat the flag as a non-nil gate without an additional nil check.
type FastPathFlag struct {
	enabled atomic.Bool
}

// NewFastPathFlag returns a FastPathFlag whose state is set to the given
// value. Callers that need the runtime Redis-backed toggle should use
// RunFastPathFlagRoutine instead; this constructor is meant for tests and
// for consumers that want to force the flag on or off.
func NewFastPathFlag(enabled bool) *FastPathFlag {
	f := &FastPathFlag{}
	f.setEnabled(enabled)
	return f
}

// Enabled reports whether the Sync fast path is currently enabled for this
// replica. A nil receiver reports false so a disabled build or test can pass
// a nil flag and skip the fast path entirely.
func (f *FastPathFlag) Enabled() bool {
	if f == nil {
		return false
	}
	return f.enabled.Load()
}

func (f *FastPathFlag) setEnabled(v bool) {
	if f == nil {
		return
	}
	f.enabled.Store(v)
}

// RunFastPathFlagRoutine starts a background goroutine that polls Redis for
// the Sync fast-path feature flag and updates the returned FastPathFlag
// accordingly. When NB_PEER_SYNC_REDIS_ADDRESS is not set the routine logs and
// returns a handle that stays permanently disabled, so every Sync falls back
// to the full network map path.
func RunFastPathFlagRoutine(ctx context.Context, interval time.Duration, redisKey string) *FastPathFlag {
	flag := &FastPathFlag{}

	redisEnvAddr := os.Getenv(fastPathRedisURLEnv)
	if redisEnvAddr == "" {
		log.Infof("Environment variable %s not set. Sync fast path disabled", fastPathRedisURLEnv)
		return flag
	}

	client, err := getFastPathRedisStore(ctx, redisEnvAddr)
	if err != nil {
		log.Errorf("Unable to connect to Redis at %v for Sync fast-path flag: %v", redisEnvAddr, err)
		return flag
	}

	if redisKey == "" {
		redisKey = DefaultFastPathRedisKey
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer func() {
			ticker.Stop()
			if err := client.Close(); err != nil {
				log.Debugf("close Sync fast-path redis client: %v", err)
			}
		}()

		refresh := func() {
			getCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			value, err := client.Get(getCtx, redisKey).Result()
			if errors.Is(err, redis.Nil) {
				flag.setEnabled(false)
				return
			}
			if err != nil {
				log.Errorf("Unable to get Sync fast-path flag from redis at %v: %v", redisEnvAddr, err)
				return
			}
			flag.setEnabled(parseFastPathFlag(value))
		}

		refresh()

		for {
			select {
			case <-ctx.Done():
				log.Infof("Stopping Sync fast-path flag routine")
				return
			case <-ticker.C:
				refresh()
			}
		}
	}()

	return flag
}

// parseFastPathFlag accepts "1" or "true" (any casing, surrounding whitespace
// tolerated) as enabled and treats every other value as disabled. Missing
// keys surface as redis.Nil in the caller and also resolve to disabled.
func parseFastPathFlag(value string) bool {
	v := strings.TrimSpace(value)
	if v == "1" {
		return true
	}
	return strings.EqualFold(v, "true")
}

func getFastPathRedisStore(ctx context.Context, redisEnvAddr string) (*redis.Client, error) {
	options, err := redis.ParseURL(redisEnvAddr)
	if err != nil {
		return nil, fmt.Errorf("parse redis fast-path url: %w", err)
	}

	client := redis.NewClient(options)
	subCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if _, err := client.Ping(subCtx).Result(); err != nil {
		return nil, err
	}

	log.WithContext(subCtx).Infof("using redis for Sync fast-path flag at %s", redisEnvAddr)
	return client, nil
}
