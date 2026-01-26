//go:build linux && !android

package rawsocket

import (
	"fmt"
	"net"
	"os"
	"syscall"

	log "github.com/sirupsen/logrus"

	nbnet "github.com/netbirdio/netbird/client/net"
)

// PrepareSenderRawSocket creates and configures raw sockets for sending both IPv4 and IPv6 packets.
// Returns IPv4 socket, IPv6 socket, and error.
func PrepareSenderRawSocket() (net.PacketConn, net.PacketConn, error) {
	ipv4Conn, err := PrepareSenderRawSocketIPv4()
	if err != nil {
		return nil, nil, fmt.Errorf("prepare IPv4 raw socket: %w", err)
	}

	ipv6Conn, err := PrepareSenderRawSocketIPv6()
	if err != nil {
		if closeErr := ipv4Conn.Close(); closeErr != nil {
			log.Warnf("failed to close IPv4 raw socket: %v", closeErr)
		}
		return nil, nil, fmt.Errorf("prepare IPv6 raw socket: %w", err)
	}

	return ipv4Conn, ipv6Conn, nil
}

// PrepareSenderRawSocketIPv4 creates and configures a raw socket for sending IPv4 packets
func PrepareSenderRawSocketIPv4() (net.PacketConn, error) {
	return prepareSenderRawSocket(syscall.AF_INET, true)
}

// PrepareSenderRawSocketIPv6 creates and configures a raw socket for sending IPv6 packets
func PrepareSenderRawSocketIPv6() (net.PacketConn, error) {
	return prepareSenderRawSocket(syscall.AF_INET6, false)
}

func prepareSenderRawSocket(family int, isIPv4 bool) (net.PacketConn, error) {
	// Create a raw socket.
	fd, err := syscall.Socket(family, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, fmt.Errorf("creating raw socket failed: %w", err)
	}

	// Set the header include option on the socket to tell the kernel that headers are included in the packet.
	// For IPv4, we need to set IP_HDRINCL. For IPv6, IPPROTO_RAW implies header inclusion.
	if isIPv4 {
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
		if err != nil {
			if closeErr := syscall.Close(fd); closeErr != nil {
				log.Warnf("failed to close raw socket fd: %v", closeErr)
			}
			return nil, fmt.Errorf("setting IP_HDRINCL failed: %w", err)
		}
	}

	// Bind the socket to the "lo" interface.
	err = syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "lo")
	if err != nil {
		if closeErr := syscall.Close(fd); closeErr != nil {
			log.Warnf("failed to close raw socket fd: %v", closeErr)
		}
		return nil, fmt.Errorf("binding to lo interface failed: %w", err)
	}

	// Set the fwmark on the socket.
	err = nbnet.SetSocketOpt(fd)
	if err != nil {
		if closeErr := syscall.Close(fd); closeErr != nil {
			log.Warnf("failed to close raw socket fd: %v", closeErr)
		}
		return nil, fmt.Errorf("setting fwmark failed: %w", err)
	}

	// Convert the file descriptor to a PacketConn.
	file := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))
	if file == nil {
		if closeErr := syscall.Close(fd); closeErr != nil {
			log.Warnf("failed to close raw socket fd: %v", closeErr)
		}
		return nil, fmt.Errorf("converting fd to file failed")
	}
	packetConn, err := net.FilePacketConn(file)
	if err != nil {
		if closeErr := file.Close(); closeErr != nil {
			log.Warnf("failed to close file: %v", closeErr)
		}
		return nil, fmt.Errorf("converting file to packet conn failed: %w", err)
	}

	return packetConn, nil
}
