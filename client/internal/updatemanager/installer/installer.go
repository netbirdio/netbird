package installer

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

const (
	LogFile = "installer.log"
)

func (u *Installer) TempDir() string {
	return u.tempDir
}

func (u *Installer) copyUpdater() (string, error) {
	if err := os.MkdirAll(u.tempDir, 0o755); err != nil {
		return "", fmt.Errorf("failed to create temp dir: %w", err)
	}

	dstPath := filepath.Join(u.tempDir, updaterBinary)

	//updaterSrcPath := "/Applications/NetBird.app/Contents/MacOS/netbird-ui"
	updaterSrcPath := "/Users/pzoli/go/src/github.com/netbirdio/netbird/client/ui/ui"
	srcFile, err := os.Open(updaterSrcPath)
	if err != nil {
		log.Debugf("Failed to open updater binary: %v", err)
		return "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dstPath)
	if err != nil {
		return "", fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dstFile.Close()

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		return "", fmt.Errorf("failed to copy file: %w", err)
	}

	if err := os.Chmod(dstPath, 0755); err != nil {
		return "", fmt.Errorf("failed to set permissions: %w", err)
	}

	return dstPath, nil
}
