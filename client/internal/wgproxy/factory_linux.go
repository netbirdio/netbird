//go:build !android

package wgproxy

import (
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/internal/wgproxy/ebpf"
	"github.com/netbirdio/netbird/client/internal/wgproxy/usp"
)

func NewFactory(userspace bool, wgPort int) *Factory {
	f := &Factory{wgPort: wgPort}

	if userspace {
		return f
	}

	ebpfProxy := ebpf.NewWGEBPFProxy(wgPort)
	err := ebpfProxy.Listen()
	if err != nil {
		log.Warnf("failed to initialize ebpf proxy, fallback to user space proxy: %s", err)
		return f
	}

	f.ebpfProxy = ebpfProxy
	return f
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
		return nil
	}
	return w.ebpfProxy.Free()
}
