//go:build e2e && unix

package harness

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const buildCacheLockRetry = 200 * time.Millisecond

// lockBuildCache takes an exclusive flock next to the buildx cache directory and
// returns the function that releases it. `go test ./e2e/...` runs each package's
// test binary in parallel, and concurrent --cache-to exports into one local
// cache directory corrupt its ingest state, so builds sharing it take turns.
func lockBuildCache(ctx context.Context, dir string) (func(), error) {
	path := filepath.Clean(dir) + ".lock"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open build cache lock %s: %w", path, err)
	}

	ticker := time.NewTicker(buildCacheLockRetry)
	defer ticker.Stop()
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, fmt.Errorf("lock build cache %s: %w", path, err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}
