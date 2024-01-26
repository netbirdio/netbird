//go:build !android

package dns

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	fileUncleanShutdownResolvConfLocation  = "/var/lib/netbird/resolv.conf"
	fileUncleanShutdownManagerTypeLocation = "/var/lib/netbird/manager"
)

func CheckUncleanShutdown(wgIface string) error {
	if _, err := os.Stat(fileUncleanShutdownResolvConfLocation); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// no file -> clean shutdown
			return nil
		} else {
			return fmt.Errorf("state: %w", err)
		}
	}

	log.Warnf("detected unclean shutdown, file %s exists", fileUncleanShutdownResolvConfLocation)

	managerData, err := os.ReadFile(fileUncleanShutdownManagerTypeLocation)
	if err != nil {
		return fmt.Errorf("read %s: %w", fileUncleanShutdownManagerTypeLocation, err)
	}

	managerFields := strings.Split(string(managerData), ",")
	if len(managerFields) < 2 {
		return errors.New("split manager data: insufficient number of fields")
	}
	osManagerTypeStr, dnsAddressStr := managerFields[0], managerFields[1]

	dnsAddress, err := netip.ParseAddr(dnsAddressStr)
	if err != nil {
		return fmt.Errorf("parse dns address %s failed: %w", dnsAddressStr, err)
	}

	log.Warnf("restoring unclean shutdown dns settings via previously detected manager: %s", osManagerTypeStr)

	// determine os manager type, so we can invoke the respective restore action
	osManagerType, err := newOsManagerType(osManagerTypeStr)
	if err != nil {
		return fmt.Errorf("detect previous host manager: %w", err)
	}

	manager, err := newHostManagerFromType(wgIface, osManagerType)
	if err != nil {
		return fmt.Errorf("create previous host manager: %w", err)
	}

	if err := manager.restoreUncleanShutdownDNS(&dnsAddress); err != nil {
		return fmt.Errorf("restore unclean shutdown backup: %w", err)
	}

	return nil
}

func createUncleanShutdownIndicator(sourcePath string, managerType osManagerType, dnsAddress string) error {
	dir := filepath.Dir(fileUncleanShutdownResolvConfLocation)
	if err := os.MkdirAll(dir, os.FileMode(0755)); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}

	if err := copyFile(sourcePath, fileUncleanShutdownResolvConfLocation); err != nil {
		return fmt.Errorf("create %s: %w", sourcePath, err)
	}

	managerData := fmt.Sprintf("%s,%s", managerType, dnsAddress)

	if err := os.WriteFile(fileUncleanShutdownManagerTypeLocation, []byte(managerData), 0644); err != nil { //nolint:gosec
		return fmt.Errorf("create %s: %w", fileUncleanShutdownManagerTypeLocation, err)
	}
	return nil
}

func removeUncleanShutdownIndicator() error {
	if err := os.Remove(fileUncleanShutdownResolvConfLocation); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", fileUncleanShutdownResolvConfLocation, err)
	}
	if err := os.Remove(fileUncleanShutdownManagerTypeLocation); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", fileUncleanShutdownManagerTypeLocation, err)
	}
	return nil
}
