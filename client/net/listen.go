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

	switch c := conn.(type) {
	case *net.UDPConn:
		// Advanced routing: plain connection
		return c, nil
	case *PacketConn:
		// Legacy routing: wrapped connection for hooks
		udpConn, ok := c.PacketConn.(*net.UDPConn)
		if !ok {
			if err := c.Close(); err != nil {
				log.Errorf("Failed to close connection: %v", err)
			}
			return nil, fmt.Errorf("expected UDPConn, got %T", c.PacketConn)
		}
		return &UDPConn{UDPConn: udpConn, ID: c.ID, seenAddrs: &sync.Map{}}, nil
	}

	if err := conn.Close(); err != nil {
		log.Errorf("failed to close connection: %v", err)
	}
	return nil, fmt.Errorf("unexpected connection type: %T", conn)
}
