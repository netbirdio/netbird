package cache_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/cache"
)

func assertGetDelConsumedOnce(ctx context.Context, t *testing.T, stores []cache.Store, key, value string) {
	t.Helper()

	const getDelAttempts = 64

	type getDelResult struct {
		value string
		found bool
		err   error
	}

	start := make(chan struct{})
	results := make(chan getDelResult, getDelAttempts)
	for i := range getDelAttempts {
		cacheStore := stores[i%len(stores)]
		go func() {
			<-start
			value, found, err := cacheStore.GetDel(ctx, key)
			results <- getDelResult{value: value, found: found, err: err}
		}()
	}
	close(start)

	consumers := 0
	for range getDelAttempts {
		result := <-results
		require.NoError(t, result.err, "concurrent GetDel failed")
		if !result.found {
			continue
		}
		consumers++
		require.Equal(t, value, result.value, "consumed value doesn't match testing data")
	}
	require.Equal(t, 1, consumers, "expected exactly one consumer")
}

func assertGetDelMisses(ctx context.Context, t *testing.T, cacheStore cache.Store, key string) {
	t.Helper()

	value, found, err := cacheStore.GetDel(ctx, key)
	require.NoError(t, err, "GetDel on a missing key should not error")
	require.False(t, found, "GetDel should not find key %q, got value %q", key, value)
	require.Empty(t, value, "GetDel should return an empty value when not found")
}
