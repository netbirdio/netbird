package iface

import "sync"

// NewWGIFace Creates a new Wireguard interface instance
func NewWGIFace(ifaceName string, address string, mtu int, wgAdapter WGAdapter) (*WGIface, error) {
	wgIface := &WGIface{
		mu: sync.Mutex{},
	}

	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return wgIface, err
	}

	wgConfigurer := newWGConfigurer(ifaceName, wgAddress, mtu, wgAdapter)

	wgIface.configurer = wgConfigurer
	wgIface.tun = newTunDevice(wgConfigurer)

	return wgIface, nil
}
