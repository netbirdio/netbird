package installer

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestRemoveUpdaterBinaryMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), updaterBinary)
	if err := removeUpdaterBinary(path); err != nil {
		t.Errorf("a missing updater binary is not a failure, got: %v", err)
	}
}
