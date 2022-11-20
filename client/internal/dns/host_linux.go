package dns

import (
	"bufio"
	"github.com/netbirdio/netbird/iface"
	log "github.com/sirupsen/logrus"
	"os"
	"strings"
)

const (
	defaultResolvConfPath = "/etc/resolv.conf"
)

const (
	fileManager osManagerType = iota
	networkManager
	systemdManager
	resolvConfManager
)

type osManagerType int

func newHostManager(wgInterface *iface.WGIface) hostManager {
	osManager := getOSDNSManagerType()
	log.Debugf("discovered mode is: %d", osManager)
	switch osManager {
	case networkManager:
		return newNetworkManagerDbusConfigurator(wgInterface)
	case systemdManager:
		return newSystemdDbusConfigurator(wgInterface)
	default:
		return newNoopHostMocker()
		//return newSystemdDbusConfigurator(wgInterface)
	}
}

func getOSDNSManagerType() osManagerType {
	file, err := os.Open(defaultResolvConfPath)
	if err != nil {
		// todo add proper error handling
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if text[0] != '#' {
			return fileManager
		}
		if strings.Contains(text, "NetworkManager") && isDbusListenerRunning(networkManagerDest, networkManagerDbusObjectNode) {
			log.Debugf("is nm running on supported v? %t", isNetworkManagerSupportedVersion())
			return networkManager
		}
		if strings.Contains(text, "systemd-resolved") && isDbusListenerRunning(systemdResolvedDest, systemdDbusObjectNode) {
			//if isDbusListenerRunning(networkManagerDest, networkManagerDbusObjectNode) {
			//	return networkManager
			//}
			return systemdManager
		}
		if strings.Contains(text, "resolvconf") {
			return resolvConfManager
		}
	}
	return fileManager
}
