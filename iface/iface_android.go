package iface

import "sync"

// NewWGIFace Creates a new Wireguard interface instance
func NewWGIFace(ifaceName string, address string, mtu int, tunAdapter TunAdapter) (*WGIface, error) {
	wgIface := &WGIface{
		mu: sync.Mutex{},
	}

	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return wgIface, err
	}

	tun := newTunDevice(wgAddress, mtu, tunAdapter)
	wgIface.tun = tun

	wgIface.configurer = newWGConfigurer(tun)

	return wgIface, nil
}
