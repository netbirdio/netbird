package requestbuffer

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBufferCoalescesConcurrentRequests(t *testing.T) {
	var fetches atomic.Int32
	buffer := New(context.Background(), "test", 50*time.Millisecond,
		func(ctx context.Context, key string) (string, error) {
			fetches.Add(1)
			return key, nil
		})

	var wg sync.WaitGroup
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			value, err := buffer.Get(context.Background(), "account")
			assert.NoError(t, err)
			assert.Equal(t, "account", value)
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), fetches.Load())
}

func TestBufferSeparatesKeys(t *testing.T) {
	keys := make(chan string, 2)
	buffer := New(context.Background(), "test", 10*time.Millisecond,
		func(ctx context.Context, key string) (string, error) {
			keys <- key
			return key, nil
		})

	var wg sync.WaitGroup
	for _, key := range []string{"a", "b"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := buffer.Get(context.Background(), key)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
	close(keys)

	var fetched []string
	for key := range keys {
		fetched = append(fetched, key)
	}
	assert.ElementsMatch(t, []string{"a", "b"}, fetched)
}

func TestBufferFetchesAfterRequest(t *testing.T) {
	var version atomic.Int32
	buffer := New(context.Background(), "test", 10*time.Millisecond,
		func(ctx context.Context, key string) (int32, error) {
			return version.Load(), nil
		})

	first, err := buffer.Get(context.Background(), "account")
	require.NoError(t, err)
	assert.Equal(t, int32(0), first)

	version.Store(1)

	second, err := buffer.Get(context.Background(), "account")
	require.NoError(t, err)
	assert.Equal(t, int32(1), second)
}

func TestBufferPropagatesError(t *testing.T) {
	fetchErr := errors.New("fetch failed")
	buffer := New(context.Background(), "test", 10*time.Millisecond,
		func(ctx context.Context, key string) (*int, error) {
			return nil, fetchErr
		})

	value, err := buffer.Get(context.Background(), "account")
	assert.ErrorIs(t, err, fetchErr)
	assert.Nil(t, value)
}

func TestBufferHonorsCallerContext(t *testing.T) {
	buffer := New(context.Background(), "test", time.Minute,
		func(ctx context.Context, key string) (string, error) {
			return key, nil
		})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := buffer.Get(ctx, "account")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestSerializedBufferQueuesRequestsDuringFetch(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var fetches, running, maxRunning atomic.Int32
		buffer := NewSerialized(context.Background(), "test", 10*time.Millisecond,
			func(ctx context.Context, key string) (int32, error) {
				n := running.Add(1)
				defer running.Add(-1)
				if n > maxRunning.Load() {
					maxRunning.Store(n)
				}
				time.Sleep(time.Second)
				return fetches.Add(1), nil
			})

		var wg sync.WaitGroup
		get := func(want int32) {
			wg.Add(1)
			go func() {
				defer wg.Done()
				value, err := buffer.Get(context.Background(), "account")
				assert.NoError(t, err)
				assert.Equal(t, want, value)
			}()
		}

		get(1)
		time.Sleep(100 * time.Millisecond)
		synctest.Wait()
		require.Equal(t, int32(1), running.Load(), "first fetch should be running")

		for range 5 {
			get(2)
		}
		wg.Wait()

		assert.Equal(t, int32(2), fetches.Load(), "requests queued during the fetch should share one fetch")
		assert.Equal(t, int32(1), maxRunning.Load(), "fetches of a key should not overlap")
	})
}

func TestUnserializedBufferOverlapsFetches(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var running, maxRunning atomic.Int32
		buffer := New(context.Background(), "test", 10*time.Millisecond,
			func(ctx context.Context, key string) (string, error) {
				n := running.Add(1)
				defer running.Add(-1)
				if n > maxRunning.Load() {
					maxRunning.Store(n)
				}
				time.Sleep(time.Second)
				return key, nil
			})

		var wg sync.WaitGroup
		wg.Go(func() {
			_, err := buffer.Get(context.Background(), "account")
			assert.NoError(t, err)
		})
		time.Sleep(100 * time.Millisecond)
		wg.Go(func() {
			_, err := buffer.Get(context.Background(), "account")
			assert.NoError(t, err)
		})
		wg.Wait()

		assert.Equal(t, int32(2), maxRunning.Load())
	})
}
