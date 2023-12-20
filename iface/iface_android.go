package iface

import (
	"fmt"

	"github.com/pion/transport/v3"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(ifaceName string, address string, mtu int, tunAdapter TunAdapter, transportNet transport.Net) (*WGIface, error) {
	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return nil, err
	}

	wgIFace := &WGIface{
		tun:           newTunDevice(wgAddress, mtu, tunAdapter, transportNet),
		userspaceBind: false,
	}
	return wgIFace, nil
}

// CreateOnAndroid creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
func (w *WGIface) CreateOnAndroid(mobileIFaceArgs MobileIFaceArguments) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	androidTun := w.tun.(*tunDevice)
	cfgr, err := androidTun.Create(mobileIFaceArgs)
	if err != nil {
		return err
	}
	w.configurer = cfgr
	return nil
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
