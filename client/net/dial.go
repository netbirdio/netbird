//go:build !ios

package net

import (
	"fmt"
	"net"
	"sync"

	"github.com/pion/transport/v3"
	log "github.com/sirupsen/logrus"
)

func DialUDP(network string, laddr, raddr *net.UDPAddr) (transport.UDPConn, error) {
	if CustomRoutingDisabled() {
		return net.DialUDP(network, laddr, raddr)
	}

	dialer := NewDialer()
	dialer.LocalAddr = laddr

	conn, err := dialer.Dial(network, raddr.String())
	if err != nil {
		return nil, fmt.Errorf("dialing UDP %s: %w", raddr.String(), err)
	}

	switch c := conn.(type) {
	case *net.UDPConn:
		// Advanced routing: plain connection
		return c, nil
	case *Conn:
		// Legacy routing: wrapped connection preserves close hooks
		udpConn, ok := c.Conn.(*net.UDPConn)
		if !ok {
			if err := conn.Close(); err != nil {
				log.Errorf("Failed to close connection: %v", err)
			}
			return nil, fmt.Errorf("expected UDP connection, got %T", c.Conn)
		}
		return &UDPConn{UDPConn: udpConn, ID: c.ID, seenAddrs: &sync.Map{}}, nil
	}

	if err := conn.Close(); err != nil {
		log.Errorf("failed to close connection: %v", err)
	}
	return nil, fmt.Errorf("unexpected connection type: %T", conn)
}

func DialTCP(network string, laddr, raddr *net.TCPAddr) (transport.TCPConn, error) {
	if CustomRoutingDisabled() {
		return net.DialTCP(network, laddr, raddr)
	}

	dialer := NewDialer()
	dialer.LocalAddr = laddr

	conn, err := dialer.Dial(network, raddr.String())
	if err != nil {
		return nil, fmt.Errorf("dialing TCP %s: %w", raddr.String(), err)
	}

	switch c := conn.(type) {
	case *net.TCPConn:
		// Advanced routing: plain connection
		return c, nil
	case *Conn:
		// Legacy routing: wrapped connection preserves close hooks
		tcpConn, ok := c.Conn.(*net.TCPConn)
		if !ok {
			if err := conn.Close(); err != nil {
				log.Errorf("Failed to close connection: %v", err)
			}
			return nil, fmt.Errorf("expected TCP connection, got %T", c.Conn)
		}
		return &TCPConn{TCPConn: tcpConn, ID: c.ID}, nil
	}
	if err := conn.Close(); err != nil {
		log.Errorf("failed to close connection: %v", err)
	}
	return nil, fmt.Errorf("unexpected connection type: %T", conn)
}
