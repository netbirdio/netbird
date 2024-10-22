package wgproxy

import (
	udpProxy "github.com/netbirdio/netbird/client/iface/wgproxy/udp"
)

// KernelFactory todo: check eBPF support on FreeBSD
type KernelFactory struct {
	wgPort int
}

func NewKernelFactory(wgPort int) *KernelFactory {
	f := &KernelFactory{
		wgPort: wgPort,
	}

	return f
}

func (w *KernelFactory) GetProxy() Proxy {
	return udpProxy.NewWGUDPProxy(w.wgPort)
}

func (w *KernelFactory) Free() error {
	return nil
}
