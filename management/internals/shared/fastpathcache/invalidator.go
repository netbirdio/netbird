// Package fastpathcache exposes the key prefixes and delete helpers for the
// Sync fast-path caches so mutation sites outside the gRPC server package
// can invalidate stale entries without a circular import on the grpc
// package that owns the read-side cache wrappers.
package fastpathcache

import (
	"context"

	"github.com/eko/gocache/lib/v4/cache"
	cachestore "github.com/eko/gocache/lib/v4/store"
	log "github.com/sirupsen/logrus"
)

const (
	// ExtraSettingsKeyPrefix matches the prefix used by the read-side
	// extraSettingsCache in management/internals/shared/grpc. Keep these in
	// sync; drift would leak stale reads on mutations.
	ExtraSettingsKeyPrefix = "extra-settings:"

	// PeerGroupsKeyPrefix matches the prefix used by the read-side
	// peerGroupsCache in management/internals/shared/grpc.
	PeerGroupsKeyPrefix = "peer-groups:"
)

// InvalidateExtraSettings removes the cached ExtraSettings entry for the
// given account from the shared cache store. Safe to call with a nil store
// and safe to call when no entry exists. Errors are swallowed at debug level
// so mutation flows never fail because of a cache hiccup.
func InvalidateExtraSettings(ctx context.Context, store cachestore.StoreInterface, accountID string) {
	if store == nil {
		return
	}
	if err := cache.New[string](store).Delete(ctx, ExtraSettingsKeyPrefix+accountID); err != nil {
		log.WithContext(ctx).Debugf("fastpathcache: invalidate extra settings for %s: %v", accountID, err)
	}
}

// InvalidatePeerGroups removes the cached peer-groups entry for a peer. Safe
// to call with a nil store and safe to call when no entry exists.
func InvalidatePeerGroups(ctx context.Context, store cachestore.StoreInterface, peerID string) {
	if store == nil {
		return
	}
	if err := cache.New[string](store).Delete(ctx, PeerGroupsKeyPrefix+peerID); err != nil {
		log.WithContext(ctx).Debugf("fastpathcache: invalidate peer groups for %s: %v", peerID, err)
	}
}
