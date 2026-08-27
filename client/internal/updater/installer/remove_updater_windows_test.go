package installer

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestRemoveUpdaterBinaryRetriesWhileLocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), updaterBinary)
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write updater: %v", err)
	}

	releaseAfter(t, lockFile(t, path), updaterRemoveDelay+50*time.Millisecond)

	if err := removeUpdaterBinary(path); err != nil {
		t.Fatalf("removeUpdaterBinary: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("updater binary still present (stat err: %v)", err)
	}
}

// TestRemoveUpdaterBinaryStaysLocked covers an updater that never releases its
// image within the retry window. Cleanup gives up quietly and leaves the file
// behind rather than reporting a failure.
func TestRemoveUpdaterBinaryStaysLocked(t *testing.T) {
	path := filepath.Join(t.TempDir(), updaterBinary)
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write updater: %v", err)
	}

	handle := lockFile(t, path)
	t.Cleanup(func() {
		if err := windows.CloseHandle(handle); err != nil {
			t.Errorf("close handle: %v", err)
		}
	})

	if err := removeUpdaterBinary(path); err != nil {
		t.Fatalf("a permanently locked updater is not a cleanup failure, got: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Errorf("locked updater binary should be left in place, stat: %v", err)
	}
}

func TestRemoveUpdaterBinaryMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), updaterBinary)
	if err := removeUpdaterBinary(path); err != nil {
		t.Errorf("a missing updater binary is not a failure, got: %v", err)
	}
}
