package main

import (
	"github.com/cilium/ebpf"
	"net"

	"syscall"
)

// Filter represents a classic BPF filter program that can be applied to a socket
type Filter struct {
	*ebpf.ProgramSpec
}

// ApplyTo applies the current filter onto the provided UDPConn
func (filter Filter) ApplyTo(conn *net.UDPConn) error {

	file, err := conn.File()
	if err != nil {
		return err
	}

	p, err := ebpf.NewProgramWithOptions(filter.ProgramSpec, ebpf.ProgramOptions{
		LogLevel: 6,
	})

	if err != nil {
		return err
	}

	if err := syscall.SetsockoptInt(int(file.Fd()), syscall.SOL_SOCKET, SO_ATTACH_BPF, p.FD()); err != nil {
		return err
	}

	return nil
}
