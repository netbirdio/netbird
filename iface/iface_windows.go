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

	wgIFace := &WGIface{}

	if netstack.IsEnabled() {
		wgIFace.tun = newTunNetstackDevice(iFaceName, wgAddress, mtu, transportNet, netstack.ListenAddr())
		wgIFace.userspaceBind = true
		return wgIFace, nil
	}

	wgIFace.tun = newTunDevice(iFaceName, wgAddress, mtu, transportNet)
	wgIFace.userspaceBind = false

	return wgIFace, nil
}

// CreateOnAndroid this function make sense on mobile only
func (w *WGIface) CreateOnAndroid([]string, string, []string) error {
	return fmt.Errorf("this function has not implemented on non mobile")
}

// GetInterfaceGUIDString returns an interface GUID. This is useful on Windows only
func (w *WGIface) GetInterfaceGUIDString() (string, error) {
	return w.tun.(*tunDevice).getInterfaceGUIDString()
}
