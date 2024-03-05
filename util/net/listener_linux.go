//go:build !android

package net

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

func NewListener() *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return SetRawSocketMark(c)
		},
	}
}

func ListenUDP(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	pc, err := NewListener().ListenPacket(context.Background(), network, laddr.String())
	if err != nil {
		return nil, fmt.Errorf("listening on %s:%s with fwmark: %w", network, laddr, err)
	}
	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("packetConn is not a *net.UDPConn")
	}
	return udpConn, nil
}
