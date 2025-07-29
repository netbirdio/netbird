//go:build windows

package net

import (
	"net"
	"sync"

	log "github.com/sirupsen/logrus"
)

var (
	vpnInterfaceIndex int    // Our VPN interface index
	vpnInterfaceName  string // Our VPN interface name for lazy init
	vpnInterfaceMu    sync.RWMutex
)

// SetVPNInterfaceIndex stores our VPN interface index
func SetVPNInterfaceIndex(index int) {
	vpnInterfaceMu.Lock()
	defer vpnInterfaceMu.Unlock()
	vpnInterfaceIndex = index
	log.Infof("Set VPN interface index to %d", index)
}

// setVPNInterfaceName stores the VPN interface name for lazy initialization
func setVPNInterfaceName(name string) {
	vpnInterfaceMu.Lock()
	defer vpnInterfaceMu.Unlock()
	vpnInterfaceName = name
	log.Debugf("Set VPN interface name to %s for lazy initialization", name)
}

// GetVPNInterfaceIndex returns our VPN interface index with lazy initialization
func GetVPNInterfaceIndex() int {
	vpnInterfaceMu.Lock()
	defer vpnInterfaceMu.Unlock()

	// If we already have the index, return it
	if vpnInterfaceIndex > 0 {
		return vpnInterfaceIndex
	}

	// Try lazy initialization if we have the interface name
	if vpnInterfaceName != "" {
		if iface, err := net.InterfaceByName(vpnInterfaceName); err == nil {
			vpnInterfaceIndex = iface.Index
			log.Debugf("Lazy initialized VPN interface index to %d", vpnInterfaceIndex)
		} else {
			log.Debugf("Lazy initialization failed for interface %s: %v", vpnInterfaceName, err)
		}
	}

	return vpnInterfaceIndex
}
