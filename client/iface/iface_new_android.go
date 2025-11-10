package iface

import (
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

	iceBind := bind.NewICEBind(opts.TransportNet, opts.FilterFn, wgAddress, opts.MTU)

	if netstack.IsEnabled() {
		wgIFace := &WGIface{
			userspaceBind:  true,
			tun:            device.NewNetstackDevice(opts.IFaceName, wgAddress, opts.WGPort, opts.WGPrivKey, opts.MTU, iceBind, netstack.ListenAddr()),
			wgProxyFactory: wgproxy.NewUSPFactory(iceBind, opts.MTU),
		}
		return wgIFace, nil
	}

	wgIFace := &WGIface{
		userspaceBind:  true,
		tun:            device.NewTunDevice(wgAddress, opts.WGPort, opts.WGPrivKey, opts.MTU, iceBind, opts.MobileArgs.TunAdapter, opts.DisableDNS),
		wgProxyFactory: wgproxy.NewUSPFactory(iceBind, opts.MTU),
	}
	return wgIFace, nil
}
