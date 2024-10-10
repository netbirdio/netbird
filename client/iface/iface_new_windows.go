package iface

import (
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

	iceBind := bind.NewICEBind(transportNet, filterFn)

	var tun WGTunDevice
	if netstack.IsEnabled() {
		tun = device.NewNetstackDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, iceBind, netstack.ListenAddr())
	} else {
		tun = device.NewTunDevice(iFaceName, wgAddress, wgPort, wgPrivKey, mtu, iceBind)
	}

	wgIFace := &WGIface{
		userspaceBind:  true,
		tun:            tun,
		wgProxyFactory: wgproxy.NewUSPFactory(iceBind),
	}
	return wgIFace, nil

}
