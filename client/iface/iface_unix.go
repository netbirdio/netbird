//go:build (linux && !android) || freebsd

package iface

import (
	"fmt"
	"runtime"

	"github.com/pion/transport/v3"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/netstack"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(iFaceName string, address string, wgPort int, wgPrivKey string, mtu int, transportNet transport.Net, args *device.MobileIFaceArguments, filterFn bind.FilterFn) (*WGIface, error) {
	wgAddress, err := device.ParseWGAddress(address)
	if err != nil {
		return nil, err
	}

	wgIFace := &WGIface{}

	// move the kernel/usp/netstack preference evaluation to upper layer
	if netstack.IsEnabled() {
		wgIFace.tun = device.NewNetstackDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, transportNet, netstack.ListenAddr(), filterFn)
		wgIFace.userspaceBind = true
		return wgIFace, nil
	}

	if device.WireGuardModuleIsLoaded() {
		wgIFace.tun = device.NewKernelDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, transportNet)
		wgIFace.userspaceBind = false
		return wgIFace, nil
	}

	if !device.ModuleTunIsLoaded() {
		return nil, fmt.Errorf("couldn't check or load tun module")
	}
	wgIFace.tun = device.NewUSPDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, transportNet, nil)
	wgIFace.userspaceBind = true
	return wgIFace, nil
}

// CreateOnAndroid this function make sense on mobile only
func (w *WGIface) CreateOnAndroid([]string, string, []string) error {
	return fmt.Errorf("CreateOnAndroid function has not implemented on %s platform", runtime.GOOS)
}
