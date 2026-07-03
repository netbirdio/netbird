package configurer

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStatsCache_CachesWithinTTL(t *testing.T) {
	var calls atomic.Int64
	c := newStatsCache(50*time.Millisecond, func() (map[string]WGStats, error) {
		calls.Add(1)
		return map[string]WGStats{"p": {}}, nil
	})

	for i := 0; i < 10; i++ {
		_, err := c.get()
		require.NoError(t, err)
	}
	require.Equal(t, int64(1), calls.Load(), "within TTL only one underlying fetch")

	time.Sleep(60 * time.Millisecond)
	_, err := c.get()
	require.NoError(t, err)
	require.Equal(t, int64(2), calls.Load(), "after TTL expiry a fresh fetch happens")
}

func TestStatsCache_SingleFlight(t *testing.T) {
	var calls atomic.Int64
	release := make(chan struct{})
	c := newStatsCache(time.Minute, func() (map[string]WGStats, error) {
		calls.Add(1)
		<-release
		return map[string]WGStats{}, nil
	})

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			_, _ = c.get()
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	require.Equal(t, int64(1), calls.Load(), "concurrent misses collapse into one fetch")
}

func TestStatsCache_ErrorNotCached(t *testing.T) {
	var calls atomic.Int64
	wantErr := errors.New("dump failed")
	c := newStatsCache(time.Minute, func() (map[string]WGStats, error) {
		calls.Add(1)
		return nil, wantErr
	})

	_, err := c.get()
	require.ErrorIs(t, err, wantErr)
	_, err = c.get()
	require.ErrorIs(t, err, wantErr)
	require.Equal(t, int64(2), calls.Load(), "errors are not cached; each call retries")
}
