package iface

import (
	"fmt"

	"github.com/pion/transport/v3"

	"github.com/netbirdio/netbird/iface/bind"
	"github.com/netbirdio/netbird/iface/device"
	"github.com/netbirdio/netbird/iface/netstack"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(iFaceName string, address string, wgPort int, wgPrivKey string, mtu int, transportNet transport.Net, args *device.MobileIFaceArguments, filterFn bind.FilterFn) (*WGIface, error) {
	wgAddress, err := device.ParseWGAddress(address)
	if err != nil {
		return nil, err
	}

	wgIFace := &WGIface{
		userspaceBind: true,
	}

	if netstack.IsEnabled() {
		wgIFace.tun = device.NewNetstackDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, transportNet, netstack.ListenAddr(), filterFn)
		return wgIFace, nil
	}

	wgIFace.tun = device.NewTunDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, transportNet, filterFn)
	return wgIFace, nil
}

// CreateOnAndroid this function make sense on mobile only
func (w *WGIface) CreateOnAndroid([]string, string, []string) error {
	return fmt.Errorf("this function has not implemented on non mobile")
}

// GetInterfaceGUIDString returns an interface GUID. This is useful on Windows only
func (w *WGIface) GetInterfaceGUIDString() (string, error) {
	return w.tun.(*device.TunDevice).GetInterfaceGUIDString()
}
