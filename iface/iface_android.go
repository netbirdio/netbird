package iface

import (
	"sync"

	"github.com/pion/transport/v2"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(ifaceName string, address string, mtu int, tunAdapter TunAdapter, transportNet transport.Net) (*WGIface, error) {
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

// SetInitialRoutes store the given routes and on the tun creation will be used
func (w *WGIface) SetInitialRoutes(routes []string) {
	w.tun.SetRoutes(routes)
}
