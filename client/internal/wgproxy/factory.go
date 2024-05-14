package wgproxy

type Factory struct {
	wgPort    int
	ebpfProxy Proxy
}

func (w *Factory) GetProxy() Proxy {
	if w.ebpfProxy != nil {
		return w.ebpfProxy
	}
	return NewWGUserSpaceProxy(w.wgPort)
}

func (w *Factory) Free() error {
	if w.ebpfProxy != nil {
		return w.ebpfProxy.Free()
	}
	return nil
}
