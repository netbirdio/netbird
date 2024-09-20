//go:build !linux || android

package wgproxy

import "github.com/netbirdio/netbird/client/internal/wgproxy/usp"

func NewFactory(_ bool, wgPort int) *Factory {
	return &Factory{wgPort: wgPort}
}

func (w *Factory) GetProxy() Proxy {
	return usp.NewWGUserSpaceProxy(w.wgPort)
}

func (w *Factory) Free() error {
	return nil
}
