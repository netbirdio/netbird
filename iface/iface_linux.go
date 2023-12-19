//go:build !android
// +build !android

package iface

import (
	"fmt"

	"github.com/pion/transport/v3"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(iFaceName string, address string, mtu int, tunAdapter TunAdapter, transportNet transport.Net) (*WGIface, error) {
	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return nil, err
	}

	wgIFace := &WGIface{}
	if WireGuardModuleIsLoaded() {
		wgIFace.tun = newTunDevice(iFaceName, wgAddress, mtu)
		wgIFace.userspaceBind = false
		return wgIFace, nil
	}

	if !tunModuleIsLoaded() {
		return nil, fmt.Errorf("couldn't check or load tun module")
	}
	wgIFace.tun = newTunUSPDevice(iFaceName, wgAddress, mtu, transportNet)
	wgIFace.userspaceBind = true
	return wgIFace, nil
}

// Create creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
func (w *WGIface) Create() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	cfgr, err := w.tun.Create()
	if err != nil {
		return err
	}
	w.configurer = cfgr
	return nil
}

// CreateOnAndroid this function make sense on mobile only
func (w *WGIface) CreateOnAndroid(mIFaceArgs MobileIFaceArguments) error {
	return fmt.Errorf("this function has not implemented on non mobile")
}

// CreateOniOS this function make sense on mobile only
func (w *WGIface) CreateOniOS(tunFd int32) error {
	return fmt.Errorf("this function has not implemented on non mobile")
}
