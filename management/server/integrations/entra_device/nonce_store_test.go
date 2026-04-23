package entra_device

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNonceStore_IssueProducesDistinctNonces(t *testing.T) {
	s := NewInMemoryNonceStore(0)
	seen := make(map[string]struct{}, 64)
	for i := 0; i < 64; i++ {
		n, exp, err := s.Issue()
		require.NoError(t, err)
		assert.NotEmpty(t, n)
		assert.True(t, exp.After(time.Now().UTC()))
		if _, dup := seen[n]; dup {
			t.Fatalf("nonce collision after %d issuances", i)
		}
		seen[n] = struct{}{}
	}
}

func TestNonceStore_ConsumeSucceedsOnce(t *testing.T) {
	s := NewInMemoryNonceStore(time.Minute)
	n, _, err := s.Issue()
	require.NoError(t, err)

	ok, err := s.Consume(n)
	require.NoError(t, err)
	assert.True(t, ok, "first consume should succeed")

	ok2, err := s.Consume(n)
	require.NoError(t, err)
	assert.False(t, ok2, "second consume on the same nonce must fail (single-use)")
}

func TestNonceStore_ConsumeRejectsUnknown(t *testing.T) {
	s := NewInMemoryNonceStore(time.Minute)
	ok, err := s.Consume("definitely-not-a-real-nonce")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestNonceStore_ConsumeRejectsExpired(t *testing.T) {
	// 1ns TTL guarantees the nonce expires before we call Consume.
	s := NewInMemoryNonceStore(time.Nanosecond)
	n, _, err := s.Issue()
	require.NoError(t, err)
	time.Sleep(2 * time.Millisecond)

	ok, err := s.Consume(n)
	require.NoError(t, err)
	assert.False(t, ok, "expired nonces must not be consumable")
}

func TestNonceStore_ConcurrentIssueAndConsume(t *testing.T) {
	// Exercise the mutex + map under light concurrency to catch obvious races.
	s := NewInMemoryNonceStore(time.Minute)
	const workers = 16
	const iters = 50

	var wg sync.WaitGroup
	errs := make(chan error, workers*iters)
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				n, _, err := s.Issue()
				if err != nil {
					errs <- err
					return
				}
				ok, err := s.Consume(n)
				if err != nil || !ok {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatalf("unexpected error during concurrent exercise: %v", e)
	}
}
