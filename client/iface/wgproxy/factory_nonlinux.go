//go:build !linux || android

package wgproxy

import (
	"github.com/netbirdio/netbird/client/iface/bind"
	"github.com/netbirdio/netbird/client/iface/wgproxy/usp"
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
	/*
		p := &proxyBind.ProxyBind{
			Bind: w.bind,
		}

	*/
	p := usp.NewWGUserSpaceProxy(w.port)
	return p
}

func (w *Factory) Free() error {
	return nil
}
