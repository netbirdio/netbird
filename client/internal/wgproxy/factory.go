package wgproxy

import (
	"github.com/netbirdio/netbird/client/internal/wgproxy/ebpf"
)

type Factory struct {
	wgPort    int
	ebpfProxy ebpf.Proxy
}
