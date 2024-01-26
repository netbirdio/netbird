package dns

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/sirupsen/logrus"
)

const (
	netbirdProgramDataLocation = "Netbird"
	fileUncleanShutdownFile    = "unclean_shutdown_dns.txt"
)

func CheckUncleanShutdown(string) error {
	file := getUncleanShutdownFile()

	if _, err := os.Stat(file); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// no file -> clean shutdown
			return nil
		} else {
			return fmt.Errorf("state: %w", err)
		}
	}

	logrus.Warnf("detected unclean shutdown, file %s exists. Restoring unclean shutdown dns settings.", file)

	guid, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("read %s: %w", file, err)
	}

	manager, err := newHostManagerWithGuid(string(guid))
	if err != nil {
		return fmt.Errorf("create host manager: %w", err)
	}

	if err := manager.restoreUncleanShutdownDNS(nil); err != nil {
		return fmt.Errorf("restore unclean shutdown backup: %w", err)
	}

	return nil
}

func createUncleanShutdownIndicator(guid string) error {
	file := getUncleanShutdownFile()

	dir := filepath.Dir(file)
	if err := os.MkdirAll(dir, os.FileMode(0755)); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}

	if err := os.WriteFile(file, []byte(guid), 0600); err != nil {
		return fmt.Errorf("create %s: %w", file, err)
	}

	return nil
}

func removeUncleanShutdownIndicator() error {
	file := getUncleanShutdownFile()

	if err := os.Remove(file); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", file, err)
	}
	return nil
}

func getUncleanShutdownFile() string {
	return filepath.Join(os.Getenv("PROGRAMDATA"), netbirdProgramDataLocation, fileUncleanShutdownFile)
}
