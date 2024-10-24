package iface

import (
	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(opts WGIFaceOpts) (*WGIface, error) {
	wgAddress, err := device.ParseWGAddress(opts.Address)
	if err != nil {
		return nil, err
	}
	iceBind := bind.NewICEBind(opts.TransportNet, opts.FilterFn)

	var tun WGTunDevice
	if netstack.IsEnabled() {
		tun = device.NewNetstackDevice(opts.IFaceName, wgAddress, opts.WGPort, opts.WGPrivKey, opts.MTU, iceBind, netstack.ListenAddr())
	} else {
		tun = device.NewTunDevice(opts.IFaceName, wgAddress, opts.WGPort, opts.WGPrivKey, opts.MTU, iceBind)
	}

	wgIFace := &WGIface{
		userspaceBind:  true,
		tun:            tun,
		wgProxyFactory: wgproxy.NewUSPFactory(iceBind),
	}
	return wgIFace, nil

}
