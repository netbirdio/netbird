//go:build !android

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

	wgIface.tun = newTunDevice(ifaceName, wgAddress, mtu, transportNet)

	wgIface.configurer = newWGConfigurer(ifaceName)
	return wgIface, nil
}
