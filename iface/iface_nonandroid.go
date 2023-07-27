//go:build !android

package iface

import (
	"fmt"
	"sync"

	"github.com/pion/transport/v2"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(iFaceName string, address string, address6 string, mtu int, tunAdapter TunAdapter, transportNet transport.Net) (*WGIface, error) {
	wgIFace := &WGIface{
		mu: sync.Mutex{},
	}

	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return wgIFace, err
	}

	var wgAddress6 *WGAddress = nil
	if address6 != "" {
		tmpWgAddress6, err := parseWGAddress(address6)
		wgAddress6 = &tmpWgAddress6
		if err != nil {
			return wgIFace, err
		}
	}

	wgIFace.tun = newTunDevice(iFaceName, wgAddress, wgAddress6, mtu, transportNet)

	wgIFace.configurer = newWGConfigurer(iFaceName)
	wgIFace.userspaceBind = !WireGuardModuleIsLoaded()
	return wgIFace, nil
}

// CreateOnMobile this function make sense on mobile only
func (w *WGIface) CreateOnMobile(mIFaceArgs MobileIFaceArguments) error {
	return fmt.Errorf("this function has not implemented on non mobile")
}

// Create creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
func (w *WGIface) Create() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.tun.Create()
}
