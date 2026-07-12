//go:build e2e

package harness

import (
	"fmt"
	"os"
	"path/filepath"
)

// repoRoot walks up from the working directory to the module root (the
// directory holding go.mod), so the Docker build context is correct no matter
// which package the test runs from.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found above %s", dir)
		}
		dir = parent
	}
}
