//go:build !android
// +build !android

package iface

import (
	"fmt"

	"github.com/pion/transport/v3"

	"github.com/netbirdio/netbird/iface/netstack"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(iFaceName string, address string, wgPort int, wgPrivKey string, mtu int, transportNet transport.Net, args *MobileIFaceArguments) (*WGIface, error) {
	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return nil, err
	}

	wgIFace := &WGIface{}

	// move the kernel/usp/netstack preference evaluation to upper layer
	if netstack.IsEnabled() {
		wgIFace.tun = newTunNetstackDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, transportNet, netstack.ListenAddr())
		wgIFace.userspaceBind = true
		return wgIFace, nil
	}

	if WireGuardModuleIsLoaded() {
		wgIFace.tun = newTunDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, transportNet)
		wgIFace.userspaceBind = false
		return wgIFace, nil
	}

	if !tunModuleIsLoaded() {
		return nil, fmt.Errorf("couldn't check or load tun module")
	}
	wgIFace.tun = newTunUSPDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, transportNet)
	wgIFace.userspaceBind = true
	return wgIFace, nil
}

// CreateOnAndroid this function make sense on mobile only
func (w *WGIface) CreateOnAndroid([]string, string, []string) error {
	return fmt.Errorf("this function has not implemented on this platform")
}
