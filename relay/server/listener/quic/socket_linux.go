//go:build linux

package quic

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

const canShareUDPPort = true

func listenUDP(address string, shared bool) (*net.UDPConn, error) {
	lc := net.ListenConfig{}
	if shared {
		lc.Control = setReusePort
	}

	pconn, err := lc.ListenPacket(context.Background(), "udp", address)
	if err != nil {
		return nil, err
	}
	udpConn, ok := pconn.(*net.UDPConn)
	if !ok {
		_ = pconn.Close()
		return nil, fmt.Errorf("%T is not a UDP socket", pconn)
	}
	return udpConn, nil
}

func setReusePort(_, _ string, c syscall.RawConn) error {
	var sockErr error
	if err := c.Control(func(fd uintptr) {
		sockErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	}); err != nil {
		return err
	}
	return sockErr
}
