//go:build !android
// +build !android

package iface

import (
	"fmt"

	"github.com/pion/transport/v3"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(iFaceName string, address string, mtu int, transportNet transport.Net, args *MobileIFaceArguments) (*WGIface, error) {
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

// CreateOnAndroid this function make sense on mobile only
func (w *WGIface) CreateOnAndroid([]string, string, []string) error {
	return fmt.Errorf("this function has not implemented on this platform")
}
