//go:build !android

package iface

import (
	"github.com/pion/transport/v2"
	"sync"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(iFaceName string, address string, mtu int, tunAdapter TunAdapter, transportNet transport.Net) (*WGIface, error) {
	wgIFace := &WGIface{
		mu: sync.Mutex{},
	}

	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return wgIFace, err
	}

	wgIFace.tun = newTunDevice(iFaceName, wgAddress, mtu, transportNet)

	wgIFace.configurer = newWGConfigurer(iFaceName)
	wgIFace.userspaceBind = !WireGuardModuleIsLoaded()
	return wgIFace, nil
}
