package iface

import (
	"fmt"
	"sync"

	"github.com/pion/transport/v3"
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

// CreateOnAndroid creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
func (w *WGIface) CreateOnAndroid(mIFaceArgs MobileIFaceArguments) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.tun.Create(mIFaceArgs)
}

// CreateOniOS creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
func (w *WGIface) CreateOniOS(tunFd int32) error {
	return fmt.Errorf("this function has not implemented on mobile")
}

// Create this function make sense on mobile only
func (w *WGIface) Create() error {
	return fmt.Errorf("this function has not implemented on mobile")
}
