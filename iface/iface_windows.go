package iface

import (
	"fmt"

	"github.com/pion/transport/v2"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(iFaceName string, address string, mtu int, transportNet transport.Net, args *MobileIFaceArguments) (*WGIface, error) {
	wgAddress, err := parseWGAddress(address)
	if err != nil {
		return nil, err
	}

	wgIFace := &WGIface{
		tun:           newTunDevice(iFaceName, wgAddress, mtu, transportNet),
		userspaceBind: false,
	}
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
