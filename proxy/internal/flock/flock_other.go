//go:build !unix

package flock

import (
	"context"
	"os"
)

// Lock is a no-op on non-Unix platforms. Returns (nil, nil) to indicate
// that no lock was acquired; callers must treat a nil file as "proceed
// without lock" rather than "lock held by someone else."
func Lock(_ context.Context, _ string) (*os.File, error) {
	return nil, nil //nolint:nilnil // intentional: nil file signals locking unsupported on this platform
}

// Unlock is a no-op on non-Unix platforms.
func Unlock(_ *os.File) error {
	return nil
}
