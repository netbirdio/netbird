package dns

import (
	"bufio"
	"github.com/netbirdio/netbird/iface"
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

const (
	systemDResolvedDest = "org.freedesktop.resolve1"
)

type osManagerType int

func newHostManager(wgInterface *iface.WGIface) hostManager {
	switch getOSDNSManagerType() {
	default:
		return nil
	}
}

func getOSDNSManagerType() osManagerType {
	file, err := os.Open(defaultResolvConfPath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if text[0] != '#' {
			return fileManager
		}
		if strings.Contains(text, "NetworkManager") {
			return networkManager
		}
		if strings.Contains(text, "systemd-resolved") {
			return systemdManager
		}
		if strings.Contains(text, "resolvconf") {
			return resolvConfManager
		}
	}
	return fileManager
}
