package iface

import (
	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
)

// NewWGIFace Creates a new WireGuard interface instance
func NewWGIFace(opts WGIFaceOpts) (*WGIface, error) {
	iceBind := bind.NewICEBind(opts.TransportNet, opts.FilterFn, opts.Address, opts.MTU)

	if netstack.IsEnabled() {
		wgIFace := &WGIface{
			userspaceBind:  true,
			tun:            device.NewNetstackDevice(opts.IFaceName, opts.Address, opts.WGPort, opts.WGPrivKey, opts.MTU, iceBind, netstack.ListenAddr()),
			wgProxyFactory: wgproxy.NewUSPFactory(iceBind, opts.MTU),
		}
		return wgIFace, nil
	}

	wgIFace := &WGIface{
		userspaceBind:  true,
		tun:            device.NewTunDevice(opts.Address, opts.WGPort, opts.WGPrivKey, opts.MTU, iceBind, opts.MobileArgs.TunAdapter, opts.DisableDNS),
		wgProxyFactory: wgproxy.NewUSPFactory(iceBind, opts.MTU),
	}
	return wgIFace, nil
}
