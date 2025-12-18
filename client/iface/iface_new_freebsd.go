//go:build freebsd

package iface

import (
	"fmt"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(opts WGIFaceOpts) (*WGIface, error) {
	wgAddress, err := wgaddr.ParseWGAddress(opts.Address)
	if err != nil {
		return nil, err
	}

	wgIFace := &WGIface{}

	if netstack.IsEnabled() {
		iceBind := bind.NewICEBind(opts.TransportNet, opts.FilterFn, wgAddress, opts.MTU)
		wgIFace.tun = device.NewNetstackDevice(opts.IFaceName, wgAddress, opts.WGPort, opts.WGPrivKey, opts.MTU, iceBind, netstack.ListenAddr())
		wgIFace.userspaceBind = true
		wgIFace.wgProxyFactory = wgproxy.NewUSPFactory(iceBind, opts.MTU)
		return wgIFace, nil
	}

	if device.ModuleTunIsLoaded() {
		iceBind := bind.NewICEBind(opts.TransportNet, opts.FilterFn, wgAddress, opts.MTU)
		wgIFace.tun = device.NewUSPDevice(opts.IFaceName, wgAddress, opts.WGPort, opts.WGPrivKey, opts.MTU, iceBind)
		wgIFace.userspaceBind = true
		wgIFace.wgProxyFactory = wgproxy.NewUSPFactory(iceBind, opts.MTU)
		return wgIFace, nil
	}

	return nil, fmt.Errorf("couldn't check or load tun module")
}
