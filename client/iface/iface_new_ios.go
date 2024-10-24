//go:build ios

package iface

import (
	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(opts WGIFaceOpts) (*WGIface, error) {
	wgAddress, err := device.ParseWGAddress(opts.Address)
	if err != nil {
		return nil, err
	}

	iceBind := bind.NewICEBind(opts.TransportNet, opts.FilterFn)

	wgIFace := &WGIface{
		tun:            device.NewTunDevice(opts.IFaceName, wgAddress, opts.WGPort, opts.WGPrivKey, iceBind, opts.MobileArgs.TunFd),
		userspaceBind:  true,
		wgProxyFactory: wgproxy.NewUSPFactory(iceBind),
	}
	return wgIFace, nil
}
