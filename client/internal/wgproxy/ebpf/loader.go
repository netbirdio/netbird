//go:build linux && !android

package ebpf

import (
	_ "embed"
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

const (
	mapKeyProxyPort uint32 = 0
	mapKeyWgPort    uint32 = 1
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 bpf src/portreplace.c --

type EBPF struct {
	link link.Link
}

func NewEBPF() *EBPF {
	return &EBPF{}
}

func (l *EBPF) Load(proxyPort, wgPort int) error {
	// it required for Docker
	err := rlimit.RemoveMemlock()
	if err != nil {
		return err
	}

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
	defer func() {
		_ = objs.Close()
	}()

	err = objs.XdpPortMap.Put(mapKeyProxyPort, uint16(proxyPort))
	if err != nil {
		return err
	}

	err = objs.XdpPortMap.Put(mapKeyWgPort, uint16(wgPort))
	if err != nil {
		return err
	}

	defer func() {
		_ = objs.XdpPortMap.Close()
	}()

	l.link, err = link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: ifce.Index,
	})
	if err != nil {
		return err
	}

	return err
}

func (l *EBPF) Free() error {
	if l.link != nil {
		return l.link.Close()
	}
	return nil
}
