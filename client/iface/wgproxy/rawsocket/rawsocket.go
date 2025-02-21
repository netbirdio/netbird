//go:build linux && !android

package rawsocket

import (
	"fmt"
	"net"
	"os"
	"syscall"

	nbnet "github.com/netbirdio/netbird/util/net"
)

func PrepareSenderRawSocket() (net.PacketConn, error) {
	// Create a raw socket.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("creating raw socket failed: %w", err)
	}

	// Set the IP_HDRINCL option on the socket to tell the kernel that headers are included in the packet.
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		return nil, fmt.Errorf("setting IP_HDRINCL failed: %w", err)
	}

	// Bind the socket to the "lo" interface.
	err = syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "lo")
	if err != nil {
		return nil, fmt.Errorf("binding to lo interface failed: %w", err)
	}

	// Set the fwmark on the socket.
	err = nbnet.SetSocketOpt(fd)
	if err != nil {
		return nil, fmt.Errorf("setting fwmark failed: %w", err)
	}

	// Convert the file descriptor to a PacketConn.
	file := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))
	if file == nil {
		return nil, fmt.Errorf("converting fd to file failed")
	}
	packetConn, err := net.FilePacketConn(file)
	if err != nil {
		return nil, fmt.Errorf("converting file to packet conn failed: %w", err)
	}

	return packetConn, nil
}
