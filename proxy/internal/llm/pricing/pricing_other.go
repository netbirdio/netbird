//go:build !unix

package pricing

import (
	"fmt"
	"time"
)

// loadPricing is unavailable on non-Unix platforms because O_NOFOLLOW and
// fstat-from-FD are required to honour the spec's symlink-safety rules. The
// proxy is only deployed on Linux today; a Windows port would need an
// equivalent path-as-handle implementation.
func loadPricing(path string) (*Table, time.Time, error) {
	return nil, time.Time{}, fmt.Errorf("llmobs pricing loader is not supported on this platform: %s", path)
}

func statMtime(path string) (time.Time, error) {
	return time.Time{}, fmt.Errorf("llmobs pricing loader is not supported on this platform: %s", path)
}
