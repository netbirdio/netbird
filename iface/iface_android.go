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

	tun := newTunDevice(wgAddress, mtu, tunAdapter, transportNet)
	wgIFace.tun = tun

	wgIFace.configurer = newWGConfigurer(tun)

	wgIFace.userspaceBind = !WireGuardModuleIsLoaded()

	return wgIFace, nil
}
