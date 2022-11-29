package dns

import (
	"bufio"
	"fmt"
	"github.com/netbirdio/netbird/iface"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
)

const (
	defaultResolvConfPath = "/etc/resolv.conf"
)

const (
	netbirdManager osManagerType = iota
	fileManager
	networkManager
	systemdManager
	resolvConfManager
)

type osManagerType int

func newHostManager(wgInterface *iface.WGIface) (hostManager, error) {
	osManager, err := getOSDNSManagerType()
	if err != nil {
		return nil, err
	}

	log.Debugf("discovered mode is: %d", osManager)
	switch osManager {
	case networkManager:
		return newNetworkManagerDbusConfigurator(wgInterface)
	case systemdManager:
		return newSystemdDbusConfigurator(wgInterface)
	default:
		return newFileConfigurator()
	}
}

func getOSDNSManagerType() (osManagerType, error) {

	file, err := os.Open(defaultResolvConfPath)
	if err != nil {
		return 0, fmt.Errorf("unable to open %s for checking owner, got error: %s", defaultResolvConfPath, err)
	}
	defer file.Close()

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
			log.Debugf("is nm running on supported v? %t", isNetworkManagerSupportedVersion())
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
	return fileManager, nil
}
