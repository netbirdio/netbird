package net

import (
	"context"
	"fmt"
	"net"
)

// ListenerConfig extends the standard net.ListenConfig with the ability to execute hooks before
// responding via the socket and after closing. This can be used to bypass the VPN for listeners.
type ListenerConfig struct {
	*net.ListenConfig
}

// NewListener creates a new ListenerConfig instance.
func NewListener() *ListenerConfig {
	listener := &ListenerConfig{
		ListenConfig: &net.ListenConfig{},
	}
	listener.init()

	return listener
}

// ListenUDP is a convenience function that wraps ListenPacket for UDP networks.
func ListenUDP(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	l := NewListener()
	pc, err := l.ListenPacket(context.Background(), network, laddr.String())
	if err != nil {
		return nil, fmt.Errorf("listening on %s:%s: %w", network, laddr, err)
	}

	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		return nil, fmt.Errorf("packetConn is not a *net.UDPConn")
	}
	return udpConn, nil
}
