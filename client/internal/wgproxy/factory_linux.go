//go:build !android

package wgproxy

import (
	"context"

	log "github.com/sirupsen/logrus"
)

func NewFactory(ctx context.Context, wgPort int) *Factory {
	f := &Factory{wgPort: wgPort}

	ebpfProxy := NewWGEBPFProxy(ctx, wgPort)
	err := ebpfProxy.listen()
	if err != nil {
		log.Warnf("failed to initialize ebpf proxy, fallback to user space proxy: %s", err)
		return f
	}

	f.ebpfProxy = ebpfProxy
	return f
}
