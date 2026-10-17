//go:build windows

package profilemanager

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// lockPrefsFile takes an exclusive lock guarding one profile's preference
// file, and returns the call that releases it. See the Unix build of this
// file for why the lock exists and why it lives in a file of its own.
//
// Windows has no mobile client and therefore no second process writing these
// files, but the lock is kept here too so the store behaves the same
// everywhere rather than being safe only where it was needed first.
func lockPrefsFile(path string) (func(), error) {
	lockPath := path + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, fmt.Errorf("create prefs directory: %w", err)
	}

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open prefs lock: %w", err)
	}

	overlapped := new(windows.Overlapped)
	if err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK,
		0, 1, 0, overlapped,
	); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock prefs: %w", err)
	}

	return func() {
		_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, new(windows.Overlapped))
		_ = f.Close()
	}, nil
}
