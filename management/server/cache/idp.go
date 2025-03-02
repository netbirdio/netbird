package cache

import (
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/store"
)

const (
	DefaultIDPCacheExpirationMax   = 7 * 24 * time.Hour // 7 days
	DefaultIDPCacheExpirationMin   = 3 * 24 * time.Hour // 3 days
	DefaultIDPCacheCleanupInterval = 30 * time.Minute
)

func NewIDPCacheManagers[T any, M any](loadableFunc cache.LoadFunction[T], store store.StoreInterface) (*cache.Cache[M], *cache.LoadableCache[T]) {
	simpleCache := cache.New[T](store)
	loadableCache := cache.NewLoadable[T](loadableFunc, simpleCache)
	return cache.New[M](store), loadableCache
}
