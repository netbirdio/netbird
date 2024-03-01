//go:build !android

package dns

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
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

func newHostManager(wgInterface string) (hostManager, error) {
	osManager, err := getOSDNSManagerType()
	if err != nil {
		return nil, err
	}

	log.Infof("System DNS manager discovered: %s", osManager)
	return newHostManagerFromType(wgInterface, osManager)
}

func newHostManagerFromType(wgInterface string, osManager osManagerType) (hostManager, error) {
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
			if checkStub() {
				return systemdManager, nil
			} else {
				return fileManager, nil
			}
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

// checkStub checks if the stub resolver is disabled in systemd-resolved. If it is disabled, we fall back to file manager.
func checkStub() bool {
	rConf, err := parseDefaultResolvConf()
	if err != nil {
		log.Warnf("failed to parse resolv conf: %s", err)
		return true
	}

	for _, ns := range rConf.nameServers {
		if ns == "127.0.0.53" {
			return true
		}
	}

	return false
}
