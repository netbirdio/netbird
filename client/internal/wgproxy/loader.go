package wgproxy

import (
	_ "embed"
	"net"

	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 bpf bpf/portreplace.c --

type eBPF struct {
	link link.Link
}

func newEBPF() *eBPF {
	return &eBPF{}
}

func (l *eBPF) load() error {
	ifce, err := net.InterfaceByName("lo")
	if err != nil {
		return err
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	err = loadBpfObjects(&objs, nil)
	if err != nil {
		return err
	}

	l.link, err = link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: ifce.Index,
	})
	return err
}

func (l *eBPF) free() {
	if l.link != nil {
		l.link.Close()
	}

	return
}
