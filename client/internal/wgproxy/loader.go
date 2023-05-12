package wgproxy

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
	"github.com/vishvananda/netlink"
)

//go:embed bpf/portreplace.o
var src []byte

type eBPF struct {
	sock int
	link netlink.Link
}

func newEBPF() *eBPF {
	return &eBPF{}
}

func (l *eBPF) load() error {
	var err error
	l.link, err = netlink.LinkByName("lo")
	if err != nil {
		return err
	}

	index := l.link.Attrs().Index
	l.sock, err = l.openRawSock(index)
	if err != nil {
		return err
	}

	mod := elf.NewModuleFromReader(bytes.NewReader(src))
	err = mod.Load(nil)
	if err != nil {
		_ = syscall.Close(l.sock)
		return err
	}

	sch := mod.SchedProgram("sched_act/socket1")
	if sch == nil {
		_ = syscall.Close(l.sock)
		return fmt.Errorf("sch program not found")
	}
	err = createQdisc(l.link)
	if err != nil {
		_ = syscall.Close(l.sock)
		return err
	}
	err = createFilter(sch.Fd(), "socket1", l.link, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		_ = deleteQdisc(l.link)
		_ = syscall.Close(l.sock)
		return err
	}
	return nil
}

func (l *eBPF) free() {
	_ = deleteQdisc(l.link)
	_ = syscall.Close(l.sock)
	return
}

func (l *eBPF) openRawSock(index int) (int, error) {
	// const ETH_P_ALL uint16 = 0x00<<8 | 0x03
	const ETH_P_ALL uint16 = 0x03

	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{}
	sll.Protocol = htons(ETH_P_ALL)
	sll.Ifindex = index
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
