package installer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/go-multierror"
)

func (u *Installer) LogFiles() []string {
	return []string{
		filepath.Join(defaultTempDir, msgLogFile),
		filepath.Join(defaultTempDir, resultFile),
		filepath.Join(defaultTempDir, LogFile),
	}
}

// CleanUpInstallerFiles
// - the installer file (exe, msi)
// - result.json file to prevent automatically showing the deprecated error state
// - the selfcopy updater.exe
func (u *Installer) CleanUpInstallerFiles() error {
	// Check if tempDir exists
	info, err := os.Stat(u.tempDir)
	if os.IsNotExist(err) || !info.IsDir() {
		return nil
	} else if err != nil {
		return err
	}

	entries, err := os.ReadDir(u.tempDir)
	if err != nil {
		return err
	}

	var merr *multierror.Error

	if err := os.Remove(filepath.Join(u.tempDir, updaterBinary)); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("failed to remove updater binary: %w", err))
	}

	if err := os.Remove(filepath.Join(u.tempDir, resultFile)); err != nil {
		merr = multierror.Append(merr, fmt.Errorf("failed to remove updater binary: %w", err))
	}

	binaryExtensions := []string{"msi", "exe"}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		for _, ext := range binaryExtensions {
			if strings.HasSuffix(strings.ToLower(name), strings.ToLower(ext)) {
				if err := os.Remove(filepath.Join(u.tempDir, name)); err != nil {
					merr = multierror.Append(merr, fmt.Errorf("failed to remove %s: %w", name, err))
				}
				break
			}
		}
	}

	return nil
}
