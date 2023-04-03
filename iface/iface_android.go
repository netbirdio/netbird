package iface

import (
	"github.com/pion/transport/v2"
	"sync"
)

// NewWGIFace Creates a new Wireguard interface instance
func NewWGIFace(ifaceName string, address string, mtu int, tunAdapter TunAdapter, transportNet transport.Net) (*WGIface, error) {
	wgIface := &WGIface{
		mu: sync.Mutex{},
	}

	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return wgIface, err
	}

	tun := newTunDevice(wgAddress, mtu, tunAdapter, transportNet)
	wgIface.tun = tun

	wgIface.configurer = newWGConfigurer(tun)

	return wgIface, nil
}
