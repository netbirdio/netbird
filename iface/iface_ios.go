//go:build ios
// +build ios

package iface

import (
	"fmt"

	"github.com/pion/transport/v3"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(iFaceName string, address string, wgPort int, wgPrivKey string, mtu int, transportNet transport.Net, args *MobileIFaceArguments) (*WGIface, error) {
	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return nil, err
	}
	wgIFace := &WGIface{
		tun:           newTunDevice(iFaceName, wgAddress, wgPort, wgPrivKey, transportNet, args.TunFd),
		userspaceBind: true,
	}
	return wgIFace, nil
}

// CreateOnAndroid creates a new Wireguard interface, sets a given IP and brings it up.
// Will reuse an existing one.
func (w *WGIface) CreateOnAndroid([]string, string, []string) error {
	return fmt.Errorf("this function has not implemented on this platform")
}
