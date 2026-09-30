//go:build e2e && unix

package harness

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLockBuildCacheSerializesHolders(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "buildx-cache")

	unlock, err := lockBuildCache(context.Background(), dir)
	require.NoError(t, err)

	// A second holder must wait while the first build still owns the cache.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err = lockBuildCache(ctx, dir)
	assert.ErrorIs(t, err, context.DeadlineExceeded, "second lock should block while the first is held")

	// Once released, the next build gets the lock.
	unlock()
	unlock2, err := lockBuildCache(context.Background(), dir)
	require.NoError(t, err, "lock should be free after release")
	unlock2()
}
