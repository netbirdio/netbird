//go:build !android

package iface

import (
	"fmt"
	"sync"

	"github.com/pion/transport/v2"
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

	tun := newTunDevice(iFaceName, wgAddress, mtu, transportNet)
	wgIFace.tun = tun
	wgIFace.configurer = newWGConfigurer(tun)
	wgIFace.userspaceBind = true
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
