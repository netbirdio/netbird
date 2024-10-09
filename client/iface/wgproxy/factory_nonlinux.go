//go:build !linux || android

package wgproxy

import (
	"github.com/netbirdio/netbird/client/iface/bind"
	proxyBind "github.com/netbirdio/netbird/client/iface/wgproxy/bind"
)

type Factory struct {
	bind *bind.ICEBind
	port int
}

func NewFactory(port int, bind *bind.ICEBind) *Factory {
	return &Factory{
		port: port,
		bind: bind,
	}
}

func (w *Factory) GetProxy() Proxy {
	return &proxyBind.ProxyBind{
		Bind: w.bind,
	}
}

func (w *Factory) Free() error {
	return nil
}
