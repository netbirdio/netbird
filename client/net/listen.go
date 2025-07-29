//go:build !ios

package net

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
)

// ListenUDP listens on the network address and returns a transport.UDPConn
// which includes support for write and close hooks.
func ListenUDP(network string, laddr *net.UDPAddr) (transport.UDPConn, error) {
	if CustomRoutingDisabled() {
		return net.ListenUDP(network, laddr)
	}

	conn, err := NewListener().ListenPacket(context.Background(), network, laddr.String())
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}

	packetConn := conn.(*PacketConn)
	udpConn, ok := packetConn.PacketConn.(*net.UDPConn)
	if !ok {
		if err := packetConn.Close(); err != nil {
			log.Errorf("Failed to close connection: %v", err)
		}
		return nil, fmt.Errorf("expected UDPConn, got different type: %T", udpConn)
	}

	return &UDPConn{UDPConn: udpConn, ID: packetConn.ID, seenAddrs: &sync.Map{}}, nil
}
