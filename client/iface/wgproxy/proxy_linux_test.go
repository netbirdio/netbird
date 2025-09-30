//go:build linux && !android

package wgproxy

import (
	"fmt"
	"net"

	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	bindproxy "github.com/netbirdio/netbird/client/iface/wgproxy/bind"
	"github.com/netbirdio/netbird/client/iface/wgproxy/ebpf"
	"github.com/netbirdio/netbird/client/iface/wgproxy/udp"
)

func seedProxies() ([]proxyInstance, error) {
	pl := make([]proxyInstance, 0)

	ebpfProxy := ebpf.NewWGEBPFProxy(51831, 1280)
	if err := ebpfProxy.Listen(); err != nil {
		return nil, fmt.Errorf("failed to initialize ebpf proxy: %s", err)
	}

	pEbpf := proxyInstance{
		name:    "ebpf kernel proxy",
		proxy:   ebpf.NewProxyWrapper(ebpfProxy),
		wgPort:  51831,
		closeFn: ebpfProxy.Free,
	}
	pl = append(pl, pEbpf)

	pUDP := proxyInstance{
		name:    "udp kernel proxy",
		proxy:   udp.NewWGUDPProxy(51832, 1280),
		wgPort:  51832,
		closeFn: func() error { return nil },
	}
	pl = append(pl, pUDP)
	return pl, nil
}

func seedProxyForProxyCloseByRemoteConn() ([]proxyInstance, error) {
	pl := make([]proxyInstance, 0)

	ebpfProxy := ebpf.NewWGEBPFProxy(51831, 1280)
	if err := ebpfProxy.Listen(); err != nil {
		return nil, fmt.Errorf("failed to initialize ebpf proxy: %s", err)
	}

	pEbpf := proxyInstance{
		name:    "ebpf kernel proxy",
		proxy:   ebpf.NewProxyWrapper(ebpfProxy),
		wgPort:  51831,
		closeFn: ebpfProxy.Free,
	}
	pl = append(pl, pEbpf)

	pUDP := proxyInstance{
		name:    "udp kernel proxy",
		proxy:   udp.NewWGUDPProxy(51832, 1280),
		wgPort:  51832,
		closeFn: func() error { return nil },
	}
	pl = append(pl, pUDP)
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
		proxy:        bindproxy.NewProxyBind(iceBind),
		endpointAddr: endpointAddress,
		closeFn:      func() error { return nil },
	}
	pl = append(pl, pBind)

	return pl, nil
}
