package wgproxy

import "context"

type Factory struct {
	wgPort    int
	ebpfProxy Proxy
}

func (w *Factory) GetProxy(ctx context.Context) Proxy {
	if w.ebpfProxy != nil {
		return w.ebpfProxy
	}
	return NewWGUserSpaceProxy(ctx, w.wgPort)
}

func (w *Factory) Free() error {
	if w.ebpfProxy != nil {
		return w.ebpfProxy.Free()
	}
	return nil
}
