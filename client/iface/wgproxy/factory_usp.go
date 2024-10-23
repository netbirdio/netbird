package wgproxy

import (
	"github.com/netbirdio/netbird/client/iface/bind"
	proxyBind "github.com/netbirdio/netbird/client/iface/wgproxy/bind"
)

type USPFactory struct {
	bind *bind.ICEBind
}

func NewUSPFactory(iceBind *bind.ICEBind) *USPFactory {
	f := &USPFactory{
		bind: iceBind,
	}
	return f
}

func (w *USPFactory) GetProxy() Proxy {
	return &proxyBind.ProxyBind{
		Bind: w.bind,
	}
}

func (w *USPFactory) Free() error {
	return nil
}
