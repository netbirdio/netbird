//go:build unix

package flock

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLockUnlock(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "test.lock")

	f, err := Lock(context.Background(), lockPath)
	require.NoError(t, err)
	require.NotNil(t, f)

	_, err = os.Stat(lockPath)
	assert.NoError(t, err, "lock file should exist")

	err = Unlock(f)
	assert.NoError(t, err)
}

func TestUnlockNil(t *testing.T) {
	err := Unlock(nil)
	assert.NoError(t, err, "unlocking nil should be a no-op")
}

func TestLockRespectsContext(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "test.lock")

	f1, err := Lock(context.Background(), lockPath)
	require.NoError(t, err)
	defer func() { require.NoError(t, Unlock(f1)) }()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	_, err = Lock(ctx, lockPath)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestLockBlocks(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "test.lock")

	f1, err := Lock(context.Background(), lockPath)
	require.NoError(t, err)

	var wg sync.WaitGroup
	wg.Add(1)

	start := time.Now()
	var elapsed time.Duration

	go func() {
		defer wg.Done()
		f2, err := Lock(context.Background(), lockPath)
		elapsed = time.Since(start)
		assert.NoError(t, err)
		if f2 != nil {
			assert.NoError(t, Unlock(f2))
		}
	}()

	// Hold the lock for 200ms, then release.
	time.Sleep(200 * time.Millisecond)
	require.NoError(t, Unlock(f1))

	wg.Wait()
	assert.GreaterOrEqual(t, elapsed, 150*time.Millisecond,
		"Lock should have blocked for at least ~200ms")
}
