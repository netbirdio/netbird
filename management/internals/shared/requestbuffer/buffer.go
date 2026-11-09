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

// Buffer batches requests per key: the first request opens a window, every
// request arriving within it joins the batch, and a single fetch serves them
// all. The fetch starts only after the window closed, so a caller never
// observes data read before its own request.
type Buffer[T any] struct {
	ctx      context.Context
	name     string
	fetch    FetchFunc[T]
	interval time.Duration

	mu      sync.Mutex
	waiting map[string][]chan result[T]
	// inFlight holds the keys with a running fetch and whether their next flush
	// is due once it ends. It is nil unless fetches are serialized.
	inFlight map[string]bool
}

type result[T any] struct {
	value T
	err   error
}

// New returns a Buffer serving batched requests through fetch. ctx bounds the
// fetches, not the callers, and must outlive them.
func New[T any](ctx context.Context, name string, interval time.Duration, fetch FetchFunc[T]) *Buffer[T] {
	return &Buffer[T]{
		ctx:      ctx,
		name:     name,
		fetch:    fetch,
		interval: interval,
		waiting:  make(map[string][]chan result[T]),
	}
}

// NewSerialized returns a Buffer like New that runs at most one fetch per key at
// a time. Requests arriving during a fetch form the next batch, which is fetched
// once both its window closed and the running fetch ended.
func NewSerialized[T any](ctx context.Context, name string, interval time.Duration, fetch FetchFunc[T]) *Buffer[T] {
	b := New(ctx, name, interval, fetch)
	b.inFlight = make(map[string]bool)
	return b
}

// Get returns the value for key, sharing one fetch with the other callers of
// the current batch. The value is shared as is, so callers must treat it as
// read-only unless the fetch hands out copies.
func (b *Buffer[T]) Get(ctx context.Context, key string) (T, error) {
	ch := make(chan result[T], 1)

	b.mu.Lock()
	b.waiting[key] = append(b.waiting[key], ch)
	first := len(b.waiting[key]) == 1
	b.mu.Unlock()

	if first {
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

func (b *Buffer[T]) flush(key string) {
	b.mu.Lock()
	if _, running := b.inFlight[key]; running {
		b.inFlight[key] = true
		b.mu.Unlock()
		return
	}
	waiting := b.waiting[key]
	delete(b.waiting, key)
	if b.inFlight != nil && len(waiting) > 0 {
		b.inFlight[key] = false
	}
	b.mu.Unlock()

	if len(waiting) == 0 {
		return
	}

	start := time.Now()
	value, err := b.fetch(b.ctx, key)
	log.WithContext(b.ctx).Tracef("%s: fetched %s for %d waiters in %s", b.name, key, len(waiting), time.Since(start))

	for _, ch := range waiting {
		ch <- result[T]{value: value, err: err}
	}

	if b.inFlight == nil {
		return
	}
	b.mu.Lock()
	due := b.inFlight[key]
	delete(b.inFlight, key)
	b.mu.Unlock()
	if due {
		go b.flush(key)
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
