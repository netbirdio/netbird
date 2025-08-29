//go:build linux && !android

package wgproxy

import (
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/wgproxy/ebpf"
	udpProxy "github.com/netbirdio/netbird/client/iface/wgproxy/udp"
)

type KernelFactory struct {
	wgPort int
	mtu    uint16

	ebpfProxy *ebpf.WGEBPFProxy
}

func NewKernelFactory(wgPort int, mtu uint16) *KernelFactory {
	f := &KernelFactory{
		wgPort: wgPort,
		mtu:    mtu,
	}

	ebpfProxy := ebpf.NewWGEBPFProxy(wgPort, mtu)
	if err := ebpfProxy.Listen(); err != nil {
		log.Infof("WireGuard Proxy Factory will produce UDP proxy")
		log.Warnf("failed to initialize ebpf proxy, fallback to user space proxy: %s", err)
		return f
	}
	log.Infof("WireGuard Proxy Factory will produce eBPF proxy")
	f.ebpfProxy = ebpfProxy
	return f
}

func (w *KernelFactory) GetProxy() Proxy {
	if w.ebpfProxy == nil {
		return udpProxy.NewWGUDPProxy(w.wgPort, w.mtu)
	}

	return ebpf.NewProxyWrapper(w.ebpfProxy)

}

func (w *KernelFactory) Free() error {
	if w.ebpfProxy == nil {
		return nil
	}
	return w.ebpfProxy.Free()
}
