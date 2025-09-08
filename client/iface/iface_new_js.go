package iface

import (
	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/netstack"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/iface/wgproxy"
)

// NewWGIFace creates a new WireGuard interface for WASM (always uses netstack mode)
func NewWGIFace(opts WGIFaceOpts) (*WGIface, error) {
	wgAddress, err := wgaddr.ParseWGAddress(opts.Address)
	if err != nil {
		return nil, err
	}

	relayBind := bind.NewRelayBindJS()

	wgIface := &WGIface{
		tun:            device.NewNetstackDevice(opts.IFaceName, wgAddress, opts.WGPort, opts.WGPrivKey, opts.MTU, relayBind, netstack.ListenAddr()),
		userspaceBind:  true,
		wgProxyFactory: wgproxy.NewUSPFactory(relayBind, opts.MTU),
	}

	return wgIface, nil
}
