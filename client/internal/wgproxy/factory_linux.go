//go:build !android

package wgproxy

import (
	log "github.com/sirupsen/logrus"
)

func NewFactory(wgPort int) *Factory {
	f := &Factory{wgPort: wgPort}

	ebpfProxy := NewWGEBPFProxy(wgPort)
	err := ebpfProxy.Listen()
	if err != nil {
		log.Errorf("failed to initialize ebpf proxy: %s", err)
		return f
	}

	f.ebpfProxy = ebpfProxy
	return f
}
