//go:build !linux

package wgproxy

import (
	"net"

	"github.com/netbirdio/netbird/client/iface/bind"
	bindproxy "github.com/netbirdio/netbird/client/iface/wgproxy/bind"
)

func seedProxies() ([]proxyInstance, error) {
	// todo extend with Bind proxy
	pl := make([]proxyInstance, 0)
	return pl, nil
}

func seedProxyForProxyCloseByRemoteConn() ([]proxyInstance, error) {
	pl := make([]proxyInstance, 0)
	iceBind := bind.NewICEBind(nil, nil)
	endpointAddress := &net.UDPAddr{
		IP:   net.IPv4(10, 0, 0, 1),
		Port: 1234,
	}

	pBind := proxyInstance{
		name:         "bind proxy",
		proxy:        bindproxy.NewProxyBind(iceBind),
		endpointAddr: endpointAddress,
		closeFn:      func() error { return nil },
	}
	pl = append(pl, pBind)
	return pl, nil
}
