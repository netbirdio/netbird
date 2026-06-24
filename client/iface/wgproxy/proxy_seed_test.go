//go:build !linux

package wgproxy

import (
	"net"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	bindproxy "github.com/netbirdio/netbird/client/iface/wgproxy/bind"
)

func seedProxies() ([]proxyInstance, error) {
	// todo extend with Bind proxy
	pl := make([]proxyInstance, 0)
	return pl, nil
}

func seedProxyForProxyCloseByRemoteConn() ([]proxyInstance, error) {
	pl := make([]proxyInstance, 0)
	wgAddress, err := wgaddr.ParseWGAddress("10.0.0.1/32")
	if err != nil {
		return nil, err
	}
	iceBind := bind.NewICEBind(nil, nil, wgAddress, 1280)
	endpointAddress := &net.UDPAddr{
		IP:   net.IPv4(10, 0, 0, 1),
		Port: 1234,
	}

	pBind := proxyInstance{
		name:         "bind proxy",
		proxy:        bindproxy.NewProxyBind(iceBind, 0),
		endpointAddr: endpointAddress,
		closeFn:      func() error { return nil },
	}
	pl = append(pl, pBind)
	return pl, nil
}
