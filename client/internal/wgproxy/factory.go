package wgproxy

import (
	"runtime"

	log "github.com/sirupsen/logrus"
)

type Factory struct {
	wgPort    int
	ebpfProxy Proxy
}

func NewFactory(wgPort int) *Factory {
	f := &Factory{wgPort: wgPort}

	if runtime.GOOS != "linux" {
		return f
	}

	ebpfProxy := NewWGEBPFProxy(wgPort)
	err := ebpfProxy.Listen()
	if err != nil {
		log.Errorf("failed to initialize ebpf proxy: %s", err)
		return f
	}

	f.ebpfProxy = ebpfProxy
	return f
}

func (w *Factory) GetProxy() Proxy {
	if w.ebpfProxy != nil {
		return w.ebpfProxy
	}
	return NewWGUserSpaceProxy(w.wgPort)
}

func (w *Factory) Free() error {
	if w.ebpfProxy != nil {
		return w.ebpfProxy.CloseConn()
	}
	return nil
}
