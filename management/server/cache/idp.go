package cache

import (
	"context"
	"fmt"
	"time"

	"github.com/eko/gocache/lib/v4/cache"
	"github.com/eko/gocache/lib/v4/marshaler"
	"github.com/eko/gocache/lib/v4/store"
	"github.com/eko/gocache/store/redis/v4"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/netbirdio/netbird/management/server/idp"
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

type IDPCache interface {
	Get(ctx context.Context, key any) (any, error)
	Set(ctx context.Context, key any, value any, duration time.Duration) error
	Delete(ctx context.Context, key any) error
}

type Marshaler interface {
	Get(ctx context.Context, key any, returnObj any) (any, error)
	Set(ctx context.Context, key, object any, options ...store.Option) error
	Delete(ctx context.Context, key any) error
}

type cacher[T any] interface {
	Get(ctx context.Context, key any) (T, error)
	Set(ctx context.Context, key any, object T, options ...store.Option) error
	Delete(ctx context.Context, key any) error
}

type marshalerWraper struct {
	cache cacher[any]
}

func (m marshalerWraper) Get(ctx context.Context, key any, _ any) (any, error) {
	return m.cache.Get(ctx, key)
}

func (m marshalerWraper) Set(ctx context.Context, key, object any, options ...store.Option) error {
	return m.cache.Set(ctx, key, object, options...)
}

func (m marshalerWraper) Delete(ctx context.Context, key any) error {
	return m.cache.Delete(ctx, key)
}

type LIDPCache struct {
	cache Marshaler
}

func (i *LIDPCache) Get(ctx context.Context, key string) (*idp.UserData, error) {
	v, err := i.cache.Get(ctx, key, new(idp.UserData))
	if err != nil {
		return nil, err
	}

	data := v.(*idp.UserData)
	return data, nil
}

func (i *LIDPCache) Set(ctx context.Context, key string, value *idp.UserData, expiration time.Duration) error {
	fmt.Printf("setting key: %s, value: %v\n", key, value)
	return i.cache.Set(ctx, key, value)
}

func (i *LIDPCache) Delete(ctx context.Context, key string) error {
	return i.cache.Delete(ctx, key)
}

func NewIDPCache(store store.StoreInterface) *LIDPCache {
	simpleCache := cache.New[any](store)
	if store.GetType() == redis.RedisType {
		m := marshaler.New(simpleCache)
		return &LIDPCache{cache: m}
	}
	return &LIDPCache{cache: &marshalerWraper{simpleCache}}
}

type IDPCacheLoadable struct {
	cache Marshaler
}

func (i *IDPCacheLoadable) Get(ctx context.Context, key string) ([]*idp.UserData, error) {
	var m []*idp.UserData
	v, err := i.cache.Get(ctx, key, &m)
	if err != nil {
		return nil, err
	}

	switch v := v.(type) {
	case []*idp.UserData:
		return v, nil
	case *[]*idp.UserData:
		return *v, nil
	case []byte:
		returnObj := &[]*idp.UserData{}
		err = msgpack.Unmarshal(v, returnObj)
		if err != nil {
			return nil, err
		}
		return *returnObj, nil
	}

	return nil, fmt.Errorf("unexpected type: %T", v)
}

func (i *IDPCacheLoadable) Set(ctx context.Context, key string, value []*idp.UserData, expiration time.Duration) error {
	return i.cache.Set(ctx, key, value)
}

func (i *IDPCacheLoadable) Delete(ctx context.Context, key string) error {
	return i.cache.Delete(ctx, key)
}

func NewIDPLoadableCache(loadableFunc cache.LoadFunction[any], store store.StoreInterface) *IDPCacheLoadable {
	simpleCache := cache.New[any](store)
	loadable := cache.NewLoadable[any](loadableFunc, simpleCache)
	if store.GetType() == redis.RedisType {
		m := marshaler.New(loadable)
		return &IDPCacheLoadable{cache: m}
	}
	return &IDPCacheLoadable{cache: &marshalerWraper{loadable}}
}
