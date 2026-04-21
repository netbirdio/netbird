package grpc

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
	log "github.com/sirupsen/logrus"
)

const (
	// DefaultFastPathFlagInterval is the default poll interval for the Sync
	// fast-path feature flag. Kept lower than the log-level overrider because
	// operators will want the toggle to propagate quickly during rollout.
	DefaultFastPathFlagInterval = 1 * time.Minute

	// DefaultFastPathFlagKey is the cache key polled by RunFastPathFlagRoutine
	// when the caller does not provide an override.
	DefaultFastPathFlagKey = "peerSyncFastPath"
)

// FastPathFlag exposes the current on/off state of the Sync fast path. The
// zero value and a nil receiver both report disabled, so callers can always
// treat the flag as a non-nil gate without an additional nil check.
type FastPathFlag struct {
	enabled atomic.Bool
}

// NewFastPathFlag returns a FastPathFlag whose state is set to the given
// value. Callers that need the runtime toggle should use
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

// RunFastPathFlagRoutine starts a background goroutine that polls the shared
// cache store for the Sync fast-path feature flag and updates the returned
// FastPathFlag accordingly. When cacheStore is nil the routine returns a
// handle that stays permanently disabled, so every Sync falls back to the
// full network map path.
//
// The shared store is Redis-backed when NB_CACHE_REDIS_ADDRESS is set (so the
// flag is toggled cluster-wide by writing the key in Redis) and falls back to
// an in-process gocache otherwise, which is enough for single-replica dev and
// test setups.
//
// The routine fails closed: any store read error (other than a plain "key not
// found" miss) disables the flag until Redis confirms it is enabled again.
func RunFastPathFlagRoutine(ctx context.Context, cacheStore store.StoreInterface, interval time.Duration, flagKey string) *FastPathFlag {
	flag := &FastPathFlag{}

	if cacheStore == nil {
		log.Infof("Shared cache store not provided. Sync fast path disabled")
		return flag
	}

	if flagKey == "" {
		flagKey = DefaultFastPathFlagKey
	}

	flagCache := cache.New[string](cacheStore)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		refresh := func() {
			getCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			value, err := flagCache.Get(getCtx, flagKey)
			if err != nil {
				var notFound *store.NotFound
				if !errors.As(err, &notFound) {
					log.Errorf("Sync fast-path flag refresh: %v; disabling fast path", err)
				}
				flag.setEnabled(false)
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
// tolerated) as enabled and treats every other value as disabled.
func parseFastPathFlag(value string) bool {
	v := strings.TrimSpace(value)
	if v == "1" {
		return true
	}
	return strings.EqualFold(v, "true")
}
