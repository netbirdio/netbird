package wgproxy

import (
	"github.com/netbirdio/netbird/client/internal/wgproxy/ebpf"
	"github.com/netbirdio/netbird/client/internal/wgproxy/usp"
)

type Factory struct {
	wgPort    int
	ebpfProxy *ebpf.WGEBPFProxy
}

func (w *Factory) GetProxy() Proxy {
	if w.ebpfProxy != nil {
		p := &ebpf.ProxyWrapper{
			WgeBPFProxy: w.ebpfProxy,
		}
		return p
	}
	return usp.NewWGUserSpaceProxy(w.wgPort)
}

func (w *Factory) Free() error {
	if w.ebpfProxy != nil {
		return w.ebpfProxy.Free()
	}
	return nil
}
