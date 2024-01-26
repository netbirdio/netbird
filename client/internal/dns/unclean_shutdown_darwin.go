//go:build !ios

package dns

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

const fileUncleanShutdownFileLocation = "/var/lib/netbird/unclean_shutdown_dns"

func CheckUncleanShutdown(string) error {
	if _, err := os.Stat(fileUncleanShutdownFileLocation); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// no file -> clean shutdown
			return nil
		} else {
			return fmt.Errorf("state: %w", err)
		}
	}

	log.Warnf("detected unclean shutdown, file %s exists. Restoring unclean shutdown dns settings.", fileUncleanShutdownFileLocation)

	manager, err := newHostManager()
	if err != nil {
		return fmt.Errorf("create host manager: %w", err)
	}

	if err := manager.restoreUncleanShutdownDNS(nil); err != nil {
		return fmt.Errorf("restore unclean shutdown backup: %w", err)
	}

	return nil
}

func createUncleanShutdownIndicator() error {
	dir := filepath.Dir(fileUncleanShutdownFileLocation)
	if err := os.MkdirAll(dir, os.FileMode(0755)); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}

	if err := os.WriteFile(fileUncleanShutdownFileLocation, nil, 0644); err != nil { //nolint:gosec
		return fmt.Errorf("create %s: %w", fileUncleanShutdownFileLocation, err)
	}

	return nil
}

func removeUncleanShutdownIndicator() error {
	if err := os.Remove(fileUncleanShutdownFileLocation); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", fileUncleanShutdownFileLocation, err)
	}
	return nil
}
