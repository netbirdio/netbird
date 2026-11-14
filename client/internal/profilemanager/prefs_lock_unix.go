//go:build !windows && !js && !plan9

package profilemanager

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// lockPrefsFile takes an exclusive advisory lock guarding one profile's
// preference file, and returns the call that releases it.
//
// The in-process mutex is not enough on the mobile clients: there the app and
// the network extension are separate processes writing the same file. Each
// write reads every section, replaces one, and writes them all back, so two
// processes saving different sections at the same time — a newly trusted SSH
// host key in the extension and an edited session list in the app — lose one
// of the two.
//
// The lock lives in a file of its own rather than on the preference file,
// because a write replaces that file and a lock held on the old inode would
// guard nothing. Locks are released by the kernel when the descriptor closes,
// so a process that dies holding one does not wedge the other.
func lockPrefsFile(path string) (func(), error) {
	lockPath := path + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, fmt.Errorf("create prefs directory: %w", err)
	}

	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open prefs lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock prefs: %w", err)
	}

	return func() {
		// Closing the descriptor drops the lock on its own; unlocking first
		// keeps the two steps explicit and ordered.
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
