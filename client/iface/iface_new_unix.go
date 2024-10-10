//go:build (linux && !android) || freebsd

package iface

import (
	"fmt"

	"github.com/pion/transport/v3"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(iFaceName string, address string, wgPort int, wgPrivKey string, mtu int, transportNet transport.Net, args *device.MobileIFaceArguments, filterFn bind.FilterFn) (*WGIface, error) {
	wgAddress, err := device.ParseWGAddress(address)
	if err != nil {
		return nil, err
	}

	wgIFace := &WGIface{}

	if netstack.IsEnabled() {
		iceBind := bind.NewICEBind(transportNet, filterFn)
		wgIFace.tun = device.NewNetstackDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, iceBind, netstack.ListenAddr())
		wgIFace.userspaceBind = true
		wgIFace.wgProxyFactory = wgproxy.NewUSPFactory(iceBind)
		return wgIFace, nil
	}

	if device.WireGuardModuleIsLoaded() {
		wgIFace.tun = device.NewKernelDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, transportNet)
		wgIFace.wgProxyFactory = wgproxy.NewKernelFactory(wgPort)
		return wgIFace, nil
	}
	if device.ModuleTunIsLoaded() {
		iceBind := bind.NewICEBind(transportNet, filterFn)
		wgIFace.tun = device.NewUSPDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, iceBind)
		wgIFace.userspaceBind = true
		wgIFace.wgProxyFactory = wgproxy.NewUSPFactory(iceBind)
		return wgIFace, nil
	}

	return nil, fmt.Errorf("couldn't check or load tun module")
}
