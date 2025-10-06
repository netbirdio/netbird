//go:build linux && !android

package wgproxy

import (
	"context"
	"os"
	"testing"

	"github.com/netbirdio/netbird/client/iface/wgproxy/ebpf"
)

func TestProxyCloseByRemoteConnEBPF(t *testing.T) {
	if os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Skip("Skipping test as it requires root privileges")
	}
	ctx := context.Background()

	ebpfProxy := ebpf.NewWGEBPFProxy(51831)
	if err := ebpfProxy.Listen(); err != nil {
		t.Fatalf("failed to initialize ebpf proxy: %s", err)
	}

	defer func() {
		if err := ebpfProxy.Free(); err != nil {
			t.Errorf("failed to free ebpf proxy: %s", err)
		}
	}()

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
		proxy:        bindproxy.NewProxyBind(iceBind, 0),
		endpointAddr: endpointAddress,
		closeFn:      func() error { return nil },
	}
	pl = append(pl, pBind)

	return pl, nil
}
