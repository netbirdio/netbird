//go:build !android
// +build !android

package iface

import (
	"context"
	"fmt"

	"github.com/pion/transport/v3"

	"github.com/netbirdio/netbird/iface/netstack"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(ctx context.Context, iFaceName string, address string, wgPort int, mtu int, transportNet transport.Net, args *MobileIFaceArguments) (*WGIface, error) {
	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return nil, err
	}

	wgIFace := &WGIface{
		wgPort: wgPort,
	}

	// move the kernel/usp/netstack preference evaluation to upper layer
	if netstack.IsEnabled() {
		wgIFace.tun = newTunNetstackDevice(iFaceName, wgAddress, mtu, transportNet, netstack.ListenAddr())
		wgIFace.userspaceBind = true
		return wgIFace, nil
	}

	if WireGuardModuleIsLoaded() {
		wgIFace.tun = newTunDevice(ctx, iFaceName, wgAddress, wgPort, mtu, transportNet)
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
