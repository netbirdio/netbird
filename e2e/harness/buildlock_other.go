//go:build e2e && !unix

package harness

import "context"

// lockBuildCache is a no-op where flock is unavailable; the e2e suite only runs
// its shared-cache builds on Linux CI.
func lockBuildCache(context.Context, string) (func(), error) {
	return func() {}, nil
}
