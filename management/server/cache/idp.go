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
	DefaultIDPCacheOpenConn        = 100
)

// UserDataCache is an interface that wraps the basic Get, Set and Delete methods for idp.UserData objects.
type UserDataCache interface {
	Get(ctx context.Context, key string) (*idp.UserData, error)
	Set(ctx context.Context, key string, value *idp.UserData, expiration time.Duration) error
	Delete(ctx context.Context, key string) error
	GetUsers(ctx context.Context, key string) ([]*idp.UserData, error)
	SetUsers(ctx context.Context, key string, users []*idp.UserData, expiration time.Duration) error
}

// UserDataCacheImpl is a struct that implements the UserDataCache interface.
type UserDataCacheImpl struct {
	cache Marshaler
}

func (u *UserDataCacheImpl) Get(ctx context.Context, key string) (*idp.UserData, error) {
	v, err := u.cache.Get(ctx, key, new(idp.UserData))
	if err != nil {
		return nil, err
	}

	data := v.(*idp.UserData)
	return data, nil
}

func (u *UserDataCacheImpl) Set(ctx context.Context, key string, value *idp.UserData, expiration time.Duration) error {
	return u.cache.Set(ctx, key, value, store.WithExpiration(expiration))
}

func (u *UserDataCacheImpl) Delete(ctx context.Context, key string) error {
	return u.cache.Delete(ctx, key)
}

func (u *UserDataCacheImpl) GetUsers(ctx context.Context, key string) ([]*idp.UserData, error) {
	var users []*idp.UserData
	v, err := u.cache.Get(ctx, key, &users)
	if err != nil {
		return nil, err
	}

	switch v := v.(type) {
	case []*idp.UserData:
		return v, nil
	case *[]*idp.UserData:
		return *v, nil
	case []byte:
		return unmarshalUserData(v)
	}

	return nil, fmt.Errorf("unexpected type: %T", v)
}

func (u *UserDataCacheImpl) SetUsers(ctx context.Context, key string, users []*idp.UserData, expiration time.Duration) error {
	return u.cache.Set(ctx, key, users, store.WithExpiration(expiration))
}

// NewUserDataCache creates a new UserDataCacheImpl object.
func NewUserDataCache(store store.StoreInterface) *UserDataCacheImpl {
	simpleCache := cache.New[any](store)
	if store.GetType() == redis.RedisType {
		m := marshaler.New(simpleCache)
		return &UserDataCacheImpl{cache: m}
	}
	return &UserDataCacheImpl{cache: &marshalerWraper{simpleCache}}
}

// AccountUserDataCache wraps the basic Get, Set and Delete methods for []*idp.UserData objects.
type AccountUserDataCache struct {
	cache Marshaler
}

func (a *AccountUserDataCache) Get(ctx context.Context, key string) ([]*idp.UserData, error) {
	var m []*idp.UserData
	v, err := a.cache.Get(ctx, key, &m)
	if err != nil {
		return nil, err
	}

	switch v := v.(type) {
	case []*idp.UserData:
		return v, nil
	case *[]*idp.UserData:
		return *v, nil
	case []byte:
		return unmarshalUserData(v)
	}

	return nil, fmt.Errorf("unexpected type: %T", v)
}

func unmarshalUserData(data []byte) ([]*idp.UserData, error) {
	returnObj := &[]*idp.UserData{}
	err := msgpack.Unmarshal(data, returnObj)
	if err != nil {
		return nil, err
	}
	return *returnObj, nil
}

func (a *AccountUserDataCache) Set(ctx context.Context, key string, value []*idp.UserData, expiration time.Duration) error {
	return a.cache.Set(ctx, key, value, store.WithExpiration(expiration))
}

func (a *AccountUserDataCache) Delete(ctx context.Context, key string) error {
	return a.cache.Delete(ctx, key)
}

// NewAccountUserDataCache creates a new AccountUserDataCache object.
func NewAccountUserDataCache(loadableFunc cache.LoadFunction[any], store store.StoreInterface) *AccountUserDataCache {
	simpleCache := cache.New[any](store)
	loadable := cache.NewLoadable[any](loadableFunc, simpleCache)
	if store.GetType() == redis.RedisType {
		m := marshaler.New(loadable)
		return &AccountUserDataCache{cache: m}
	}
	return &AccountUserDataCache{cache: &marshalerWraper{loadable}}
}
