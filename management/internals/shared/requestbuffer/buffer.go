// Package requestbuffer coalesces concurrent reads of the same expensive
// resource into a single fetch.
package requestbuffer

import (
	"context"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// FetchFunc reads the resource identified by key.
type FetchFunc[T any] func(ctx context.Context, key string) (T, error)

// MergingFetchFunc reads the resource identified by key for the merged
// request of a batch.
type MergingFetchFunc[R, T any] func(ctx context.Context, key string, request R) (T, error)

// MergeFunc folds a request into the request already batched for its key and
// returns the result. It may modify and return batched.
type MergeFunc[R any] func(batched, request R) R

// Buffer batches requests per key: the first request opens a window, every
// request arriving within it joins the batch, and a single fetch serves them
// all. The fetch starts only after the window closed, so a caller never
// observes data read before its own request.
type Buffer[T any] struct {
	merging *MergingBuffer[struct{}, T]
}

// New returns a Buffer serving batched requests through fetch. ctx bounds the
// fetches, not the callers, and must outlive them.
func New[T any](ctx context.Context, name string, interval time.Duration, fetch FetchFunc[T]) *Buffer[T] {
	return &Buffer[T]{
		merging: NewMerging(ctx, name, interval,
			func(struct{}, struct{}) struct{} { return struct{}{} },
			func(ctx context.Context, key string, _ struct{}) (T, error) { return fetch(ctx, key) },
		),
	}
}

// Get returns the value for key, sharing one fetch with the other callers of
// the current batch. The value is shared as is, so callers must treat it as
// read-only unless the fetch hands out copies.
func (b *Buffer[T]) Get(ctx context.Context, key string) (T, error) {
	return b.merging.Get(ctx, key, struct{}{})
}

// MergingBuffer batches requests per key like Buffer, but every request
// carries an argument: the arguments of a batch are merged, and the single
// fetch reads for the merged argument and serves every caller of the batch.
// merge must only widen a request, so the value fetched for the merged
// request satisfies each of its parts.
type MergingBuffer[R, T any] struct {
	ctx      context.Context
	name     string
	merge    MergeFunc[R]
	fetch    MergingFetchFunc[R, T]
	interval time.Duration

	mu      sync.Mutex
	waiting map[string]*batch[R, T]
}

type batch[R, T any] struct {
	request R
	waiters []chan result[T]
}

type result[T any] struct {
	value T
	err   error
}

// NewMerging returns a MergingBuffer serving batched requests through fetch.
// ctx bounds the fetches, not the callers, and must outlive them.
func NewMerging[R, T any](ctx context.Context, name string, interval time.Duration, merge MergeFunc[R], fetch MergingFetchFunc[R, T]) *MergingBuffer[R, T] {
	return &MergingBuffer[R, T]{
		ctx:      ctx,
		name:     name,
		merge:    merge,
		fetch:    fetch,
		interval: interval,
		waiting:  make(map[string]*batch[R, T]),
	}
}

// Get returns the value for key read for a request covering request, sharing
// one fetch with the other callers of the current batch. The request is
// handed over to the buffer and must not be used by the caller afterwards.
// The value is shared as is, so callers must treat it as read-only.
func (b *MergingBuffer[R, T]) Get(ctx context.Context, key string, request R) (T, error) {
	ch := make(chan result[T], 1)

	b.mu.Lock()
	pending, ok := b.waiting[key]
	if ok {
		pending.request = b.merge(pending.request, request)
	} else {
		pending = &batch[R, T]{request: request}
		b.waiting[key] = pending
	}
	pending.waiters = append(pending.waiters, ch)
	b.mu.Unlock()

	if !ok {
		time.AfterFunc(b.interval, func() { b.flush(key) })
	}

	select {
	case res := <-ch:
		return res.value, res.err
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

func (b *MergingBuffer[R, T]) flush(key string) {
	b.mu.Lock()
	pending := b.waiting[key]
	delete(b.waiting, key)
	b.mu.Unlock()

	if pending == nil {
		return
	}

	start := time.Now()
	value, err := b.fetch(b.ctx, key, pending.request)
	log.WithContext(b.ctx).Tracef("%s: fetched %s for %d waiters in %s", b.name, key, len(pending.waiters), time.Since(start))

	for _, ch := range pending.waiters {
		ch <- result[T]{value: value, err: err}
	}
}

// Interval reads a buffer interval from envVar, falling back to def.
func Interval(ctx context.Context, envVar string, def time.Duration) time.Duration {
	value := os.Getenv(envVar)
	interval, err := time.ParseDuration(value)
	if err != nil {
		if value != "" {
			log.WithContext(ctx).Warnf("failed to parse %s: %s", envVar, err)
		}
		return def
	}
	return interval
}
