package wgproxy

import (
	log "github.com/sirupsen/logrus"

	proxyBind "github.com/netbirdio/netbird/client/iface/wgproxy/bind"
)

type USPFactory struct {
	bind proxyBind.Bind
	mtu  uint16
}

func NewUSPFactory(bind proxyBind.Bind, mtu uint16) *USPFactory {
	log.Infof("WireGuard Proxy Factory will produce bind proxy")
	f := &USPFactory{
		bind: bind,
		mtu:  mtu,
	}
	return f
}

func (w *USPFactory) GetProxy() Proxy {
	return proxyBind.NewProxyBind(w.bind, w.mtu)
}

// GetProxyPort returns 0 as userspace WireGuard doesn't use a separate proxy port.
func (w *USPFactory) GetProxyPort() uint16 {
	return 0
}

func (w *USPFactory) Free() error {
	return nil
}
