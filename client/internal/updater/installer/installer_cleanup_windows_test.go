package installer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// lockFile opens path without FILE_SHARE_DELETE, so os.Remove fails the way it does
// while the updater process still holds its own image.
func lockFile(t *testing.T, path string) windows.Handle {
	t.Helper()

	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatalf("convert path: %v", err)
	}

	handle, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatalf("lock %s: %v", path, err)
	}
	return handle
}

// releaseAfter closes the handle once the delay has passed, standing in for the
// updater process finally exiting.
func releaseAfter(t *testing.T, handle windows.Handle, delay time.Duration) {
	t.Helper()

	released := make(chan struct{})
	t.Cleanup(func() { <-released })

	go func() {
		defer close(released)
		time.Sleep(delay)
		if err := windows.CloseHandle(handle); err != nil {
			t.Errorf("close handle: %v", err)
		}
	}()
}

// TestCleanUpInstallerFilesLockedUpdater covers the post-update cleanup race: the
// daemon cleans up at startup while the updater that restarted it is still exiting,
// so the updater image is locked and Windows refuses the delete. Cleanup must wait
// the lock out instead of reporting a failure and leaving the binary behind.
func TestCleanUpInstallerFilesLockedUpdater(t *testing.T) {
	tempDir := t.TempDir()
	path := filepath.Join(tempDir, updaterBinary)
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write updater: %v", err)
	}

	releaseAfter(t, lockFile(t, path), 300*time.Millisecond)

	u := NewWithDir(tempDir)
	if err := u.CleanUpInstallerFiles(); err != nil {
		t.Fatalf("cleanup must tolerate a still-locked updater: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("updater binary still present (stat err: %v)", err)
	}
}
