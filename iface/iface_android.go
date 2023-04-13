package iface

import (
	"sync"

	"github.com/pion/transport/v2"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(ifaceName string, address string, mtu int, routes []string, tunAdapter TunAdapter, transportNet transport.Net) (*WGIface, error) {
	wgIFace := &WGIface{
		mu: sync.Mutex{},
	}

	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return wgIFace, err
	}

	tun := newTunDevice(wgAddress, mtu, routes, tunAdapter, transportNet)
	wgIFace.tun = tun

	wgIFace.configurer = newWGConfigurer(tun)

	wgIFace.userspaceBind = !WireGuardModuleIsLoaded()

	return wgIFace, nil
}
