//go:build !android

package wgproxy

import (
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface/bind"
	proxyBind "github.com/netbirdio/netbird/client/iface/wgproxy/bind"
	"github.com/netbirdio/netbird/client/iface/wgproxy/ebpf"
	"github.com/netbirdio/netbird/client/iface/wgproxy/usp"
)

type proxyMode int

const (
	proxyModeUDP proxyMode = iota
	proxyModeEBPF
	proxyModeBind
)

type Factory struct {
	wgPort int
	mode   proxyMode

	ebpfProxy *ebpf.WGEBPFProxy
	bind      *bind.ICEBind
}

func NewFactory(wgPort int, iceBind *bind.ICEBind) *Factory {
	f := &Factory{
		wgPort: wgPort,
	}

	if iceBind != nil {
		f.bind = iceBind
		f.mode = proxyModeBind
		return f
	}

	ebpfProxy := ebpf.NewWGEBPFProxy(wgPort)
	if err := ebpfProxy.Listen(); err != nil {
		log.Warnf("failed to initialize ebpf proxy, fallback to user space proxy: %s", err)
		f.mode = proxyModeUDP
		return f
	}
	f.ebpfProxy = ebpfProxy
	f.mode = proxyModeEBPF
	return f
}

func (w *Factory) GetProxy() Proxy {
	switch w.mode {
	case proxyModeUDP:
		return usp.NewWGUserSpaceProxy(w.wgPort)
	case proxyModeEBPF:
		p := &ebpf.ProxyWrapper{
			WgeBPFProxy: w.ebpfProxy,
		}
		return p
	case proxyModeBind:
		p := &proxyBind.ProxyBind{
			Bind: w.bind,
		}
		return p
	default:
		return nil
	}
}

func (w *Factory) Free() error {
	if w.ebpfProxy == nil {
		return nil
	}
	return w.ebpfProxy.Free()
}
