package settingoverrider

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

const (
	DefaultInterval = 5 * time.Minute
)

// ApplyFunc is called with the raw Redis string value whenever it changes.
// The function is responsible for parsing and applying the value.
// Return an error to log a warning without stopping the polling loop.
type ApplyFunc func(value string) error

// Overrider holds a shared Redis connection and allows registering
// individual settings that are polled independently.
type Overrider struct {
	client *redis.Client
	cancel context.CancelFunc
	ctx    context.Context
	noop   bool
}

// New creates an Overrider by connecting to Redis at the given address.
// The address should follow the Redis URL format (e.g. "redis://localhost:6379").
func New(ctx context.Context, redisAddr string) (*Overrider, error) {
	if redisAddr == "" {
		return nil, fmt.Errorf("redis address is empty")
	}

	options, err := redis.ParseURL(redisAddr)
	if err != nil {
		return nil, fmt.Errorf("parsing redis address: %w", err)
	}

	client := redis.NewClient(options)

	pingCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if _, err := client.Ping(pingCtx).Result(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("connecting to redis: %w", err)
	}

	oCtx, oCancel := context.WithCancel(ctx)

	return &Overrider{client: client, cancel: oCancel, ctx: oCtx}, nil
}

// NewNoop returns an Overrider that does nothing.
// Poll calls are silently ignored and Close is a no-op.
func NewNoop() *Overrider {
	return &Overrider{noop: true}
}

// Close stops all polling goroutines and closes the underlying Redis client.
func (o *Overrider) Close() error {
	if o.noop {
		return nil
	}
	o.cancel()
	return o.client.Close()
}

// Poll starts a background goroutine that polls a single Redis key at the given interval
// and calls apply whenever the value changes. The goroutine stops when the Overrider is closed.
func (o *Overrider) Poll(interval time.Duration, redisKey string, apply ApplyFunc) {
	if o.noop {
		return
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		var lastSeen *string

		for {
			select {
			case <-o.ctx.Done():
				log.WithContext(o.ctx).Infof("Stopping settings overrider for key %q", redisKey)
				return
			case <-ticker.C:
				getCtx, cancel := context.WithTimeout(o.ctx, 5*time.Second)
				val, err := o.client.Get(getCtx, redisKey).Result()
				cancel()

				if errors.Is(err, redis.Nil) || val == "" {
					continue
				}
				if err != nil {
					if o.ctx.Err() != nil {
						return
					}
					log.WithContext(o.ctx).Errorf("Unable to get setting %q from Redis: %v", redisKey, err)
					continue
				}

				if lastSeen != nil && *lastSeen == val {
					continue
				}

				if err := apply(val); err != nil {
					log.WithContext(o.ctx).Warnf("Failed to apply setting %q with value %q: %v", redisKey, val, err)
					continue
				}

				lastSeen = &val
			}
		}
	}()
}
