//go:build !android

package iface

import "sync"

// NewWGIFace Creates a new Wireguard interface instance
func NewWGIFace(ifaceName string, address string, mtu int, routes []string, tunAdapter TunAdapter) (*WGIface, error) {
	wgIface := &WGIface{
		mu: sync.Mutex{},
	}

	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return wgIface, err
	}

	wgIface.tun = newTunDevice(ifaceName, wgAddress, mtu)

	wgIface.configurer = newWGConfigurer(ifaceName)
	return wgIface, nil
}
