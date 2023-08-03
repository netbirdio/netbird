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
		log.Warnf("failed to initialize ebpf proxy, fallback to user space proxy: %s", err)
		return f
	}

	f.ebpfProxy = ebpfProxy
	return f
}
