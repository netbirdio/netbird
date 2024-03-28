package net

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
)

// Dialer extends the standard net.Dialer with the ability to execute hooks before
// and after connections. This can be used to bypass the VPN for connections using this dialer.
type Dialer struct {
	*net.Dialer
}

// NewDialer returns a customized net.Dialer with overridden Control method
func NewDialer() *Dialer {
	dialer := &Dialer{
		Dialer: &net.Dialer{},
	}
	dialer.init()

	return dialer
}

func DialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	dialer := NewDialer()
	dialer.LocalAddr = laddr

	conn, err := dialer.Dial(network, raddr.String())
	if err != nil {
		return nil, fmt.Errorf("dialing UDP %s: %w", raddr.String(), err)
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		if err := conn.Close(); err != nil {
			log.Errorf("Failed to close connection: %v", err)
		}
		return nil, fmt.Errorf("expected UDP connection, got different type")
	}

	return udpConn, nil
}

func DialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	dialer := NewDialer()
	dialer.LocalAddr = laddr

	conn, err := dialer.Dial(network, raddr.String())
	if err != nil {
		return nil, fmt.Errorf("dialing TCP %s: %w", raddr.String(), err)
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		if err := conn.Close(); err != nil {
			log.Errorf("Failed to close connection: %v", err)
		}
		return nil, fmt.Errorf("expected TCP connection, got different type")
	}

	return tcpConn, nil
}
