//go:build !android

package dns

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/iface"
)

const (
	defaultResolvConfPath = "/etc/resolv.conf"

	fileUncleanShutdownResolvConfLocation  = "/var/lib/netbird/resolv.conf"
	fileUncleanShutdownManagerTypeLocation = "/var/lib/netbird/manager-type"
)

const (
	netbirdManager osManagerType = iota
	fileManager
	networkManager
	systemdManager
	resolvConfManager
)

var ErrUnknownOsManagerType = errors.New("unknown os manager type")

type osManagerType int

func newOsManagerType(osManager string) (osManagerType, error) {
	switch osManager {
	case "netbird":
		return fileManager, nil
	case "file":
		return netbirdManager, nil
	case "networkManager":
		return networkManager, nil
	case "systemd":
		return systemdManager, nil
	case "resolvconf":
		return resolvConfManager, nil
	default:
		return 0, ErrUnknownOsManagerType
	}
}

func (t osManagerType) String() string {
	switch t {
	case netbirdManager:
		return "netbird"
	case fileManager:
		return "file"
	case networkManager:
		return "networkManager"
	case systemdManager:
		return "systemd"
	case resolvConfManager:
		return "resolvconf"
	default:
		return "unknown"
	}
}

func newHostManager(wgInterface WGIface) (hostManager, error) {
	osManager, err := getOSDNSManagerType()
	if err != nil {
		return nil, err
	}

	log.Debugf("discovered mode is: %s", osManager)
	return newHostManagerFromType(wgInterface, osManager)
}

func newHostManagerFromType(wgInterface WGIface, osManager osManagerType) (hostManager, error) {
	switch osManager {
	case networkManager:
		return newNetworkManagerDbusConfigurator(wgInterface)
	case systemdManager:
		return newSystemdDbusConfigurator(wgInterface)
	case resolvConfManager:
		return newResolvConfConfigurator(wgInterface)
	default:
		return newFileConfigurator()
	}
}

func getOSDNSManagerType() (osManagerType, error) {
	file, err := os.Open(defaultResolvConfPath)
	if err != nil {
		return 0, fmt.Errorf("unable to open %s for checking owner, got error: %w", defaultResolvConfPath, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Errorf("close file %s: %s", defaultResolvConfPath, err)
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if len(text) == 0 {
			continue
		}
		if text[0] != '#' {
			return fileManager, nil
		}
		if strings.Contains(text, fileGeneratedResolvConfContentHeader) {
			return netbirdManager, nil
		}
		if strings.Contains(text, "NetworkManager") && isDbusListenerRunning(networkManagerDest, networkManagerDbusObjectNode) && isNetworkManagerSupported() {
			return networkManager, nil
		}
		if strings.Contains(text, "systemd-resolved") && isDbusListenerRunning(systemdResolvedDest, systemdDbusObjectNode) {
			return systemdManager, nil
		}
		if strings.Contains(text, "resolvconf") {
			if isDbusListenerRunning(systemdResolvedDest, systemdDbusObjectNode) {
				var value string
				err = getSystemdDbusProperty(systemdDbusResolvConfModeProperty, &value)
				if err == nil {
					if value == systemdDbusResolvConfModeForeign {
						return systemdManager, nil
					}
				}
				log.Errorf("got an error while checking systemd resolv conf mode, error: %s", err)
			}
			return resolvConfManager, nil
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return 0, fmt.Errorf("scan: %w", err)
	}

	return fileManager, nil
}

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

	osManagerTypeStr, err := os.ReadFile(fileUncleanShutdownManagerTypeLocation)
	if err != nil {
		return fmt.Errorf("read %s: %w", fileUncleanShutdownManagerTypeLocation, err)
	}

	log.Warnf("restoring unclean shutdown dns settings via previously detected manager: %s", osManagerTypeStr)

	// determine os manager type, so we can invoke the respective restore action
	osManagerType, err := newOsManagerType(string(osManagerTypeStr))
	if err != nil {
		return fmt.Errorf("detect previous host manager: %w", err)
	}

	// the only real thing we need is the interface name
	dummyInt, err := iface.NewWGIFace(wgIface, "0.0.0.0/32", 0, "", iface.DefaultMTU, &stdnet.Net{}, nil)
	if err != nil {
		return fmt.Errorf("create dummy int: %w", err)
	}

	manager, err := newHostManagerFromType(dummyInt, osManagerType)
	if err != nil {
		return fmt.Errorf("create previous host manager: %w", err)
	}

	if err := manager.restoreUncleanShutdownBackup(); err != nil {
		return fmt.Errorf("restore unclean shutdown backup: %w", err)
	}

	return removeUncleanShutdownBackup()
}

func createUncleanShutdownBackup(sourcePath string, managerType osManagerType) error {
	dir := filepath.Dir(fileUncleanShutdownResolvConfLocation)
	if err := os.MkdirAll(dir, os.FileMode(0755)); err != nil {
		return fmt.Errorf("create dir %s: %w", dir, err)
	}

	if err := copyFile(sourcePath, fileUncleanShutdownResolvConfLocation); err != nil {
		return fmt.Errorf("create %s: %w", sourcePath, err)
	}

	if err := os.WriteFile(fileUncleanShutdownManagerTypeLocation, []byte(managerType.String()), 0644); err != nil { //nolint:gosec
		return fmt.Errorf("create %s: %w", fileUncleanShutdownManagerTypeLocation, err)
	}
	return nil
}

func removeUncleanShutdownBackup() error {
	if err := os.Remove(fileUncleanShutdownResolvConfLocation); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", fileUncleanShutdownResolvConfLocation, err)
	}
	if err := os.Remove(fileUncleanShutdownManagerTypeLocation); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove %s: %w", fileUncleanShutdownManagerTypeLocation, err)
	}
	return nil
}
