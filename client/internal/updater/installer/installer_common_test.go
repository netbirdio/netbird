//go:build windows || darwin

package installer

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCleanUpInstallerFiles checks that cleanup removes the updater copy and the
// downloaded installer while leaving the logs and the result file for the daemon.
func TestCleanUpInstallerFiles(t *testing.T) {
	tempDir := t.TempDir()

	installers := make([]string, 0, len(binaryExtensions))
	for _, ext := range binaryExtensions {
		installers = append(installers, "netbird_installer."+ext)
	}

	kept := []string{"installer.log", "result.json"}

	for _, name := range append(append([]string{updaterBinary}, installers...), kept...) {
		if err := os.WriteFile(filepath.Join(tempDir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	u := NewWithDir(tempDir)
	if err := u.CleanUpInstallerFiles(); err != nil {
		t.Fatalf("CleanUpInstallerFiles: %v", err)
	}

	for _, name := range append([]string{updaterBinary}, installers...) {
		if _, err := os.Stat(filepath.Join(tempDir, name)); !os.IsNotExist(err) {
			t.Errorf("%s was not removed (stat err: %v)", name, err)
		}
	}

	for _, name := range kept {
		if _, err := os.Stat(filepath.Join(tempDir, name)); err != nil {
			t.Errorf("%s should have been kept: %v", name, err)
		}
	}
}

func TestCleanUpInstallerFilesMissingTempDir(t *testing.T) {
	u := NewWithDir(filepath.Join(t.TempDir(), "does-not-exist"))
	if err := u.CleanUpInstallerFiles(); err != nil {
		t.Errorf("a missing temp dir is not a cleanup failure, got: %v", err)
	}
}
