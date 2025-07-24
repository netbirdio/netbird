package wgproxy

import (
	log "github.com/sirupsen/logrus"

	udpProxy "github.com/netbirdio/netbird/client/iface/wgproxy/udp"
)

// KernelFactory todo: check eBPF support on FreeBSD
type KernelFactory struct {
	wgPort int
	mtu    uint16
}

func NewKernelFactory(wgPort int, mtu uint16) *KernelFactory {
	log.Infof("WireGuard Proxy Factory will produce UDP proxy")
	f := &KernelFactory{
		wgPort: wgPort,
		mtu:    mtu,
	}

	return f
}

func (w *KernelFactory) GetProxy() Proxy {
	return udpProxy.NewWGUDPProxy(w.wgPort, w.mtu)
}

func (w *KernelFactory) Free() error {
	return nil
}
