//go:build linux && !android

package rawsocket

import (
	"fmt"
	"net"
	"os"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	nbnet "github.com/netbirdio/netbird/client/net"
)

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
	// For IPv4, we need to set IP_HDRINCL. For IPv6, we need to set IPV6_HDRINCL to accept application-provided IPv6 headers.
	if isIPv4 {
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, unix.IP_HDRINCL, 1)
		if err != nil {
			if closeErr := syscall.Close(fd); closeErr != nil {
				log.Warnf("failed to close raw socket fd: %v", closeErr)
			}
			return nil, fmt.Errorf("setting IP_HDRINCL failed: %w", err)
		}
	} else {
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1)
		if err != nil {
			if closeErr := syscall.Close(fd); closeErr != nil {
				log.Warnf("failed to close raw socket fd: %v", closeErr)
			}
			return nil, fmt.Errorf("setting IPV6_HDRINCL failed: %w", err)
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

	// Close the original file to release the FD (net.FilePacketConn duplicates it)
	if closeErr := file.Close(); closeErr != nil {
		log.Warnf("failed to close file after creating packet conn: %v", closeErr)
	}

	return packetConn, nil
}
