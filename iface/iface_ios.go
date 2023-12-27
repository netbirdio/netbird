//go:build ios
// +build ios

package iface

import (
	"context"
	"fmt"

	"github.com/pion/transport/v3"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(ctx context.Context, ifaceName string, address string, wgPort int, mtu int, transportNet transport.Net, mobileIFaceArgs *MobileIFaceArguments) (*WGIface, error) {
	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return nil, err
	}

	wgIFace := &WGIface{
		tun:           newTunDevice(ifaceName, wgAddress, transportNet, mobileIFaceArgs.TunFd),
		userspaceBind: false,
	}
	return wgIFace, nil
}

// CreateOnAndroid creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
func (w *WGIface) CreateOnAndroid([]string, string, []string) error {
	return fmt.Errorf("this function has not implemented on this platform")
}
