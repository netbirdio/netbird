//go:build ios
// +build ios

package iface

import (
	"fmt"

	"github.com/pion/transport/v2"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(ifaceName string, address string, mtu int, transportNet transport.Net) (*WGIface, error) {
	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return nil, err
	}

	wgIFace := &WGIface{
		tun:           newTunDevice(ifaceName, wgAddress, transportNet),
		userspaceBind: false,
	}
	return wgIFace, nil
}

// CreateOniOS creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
func (w *WGIface) CreateOniOS(tunFd int32) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	cfgr, err := w.tun.Create(tunFd)
	if err != nil {
		return err
	}
	w.configurer = cfgr
	return nil
}

// CreateOnAndroid creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
func (w *WGIface) CreateOnAndroid(mIFaceArgs MobileIFaceArguments) error {
	return fmt.Errorf("this function has not implemented on mobile")
}

// Create this function make sense on mobile only
func (w *WGIface) Create() error {
	return fmt.Errorf("this function has not implemented on mobile")
}
