package cache

import (
	"context"

	"github.com/eko/gocache/lib/v4/store"
)

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
