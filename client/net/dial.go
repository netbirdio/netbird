//go:build !ios

package net

import (
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
)

func DialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	if CustomRoutingDisabled() {
		return net.DialUDP(network, laddr, raddr)
	}

	dialer := NewDialer()
	dialer.LocalAddr = laddr

	conn, err := dialer.Dial(network, raddr.String())
	if err != nil {
		return nil, fmt.Errorf("dialing UDP %s: %w", raddr.String(), err)
	}

	udpConn, ok := conn.(*Conn).Conn.(*net.UDPConn)
	if !ok {
		if err := conn.Close(); err != nil {
			log.Errorf("Failed to close connection: %v", err)
		}
		return nil, fmt.Errorf("expected UDP connection, got different type: %T", conn)
	}

	return udpConn, nil
}

func DialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	if CustomRoutingDisabled() {
		return net.DialTCP(network, laddr, raddr)
	}

	dialer := NewDialer()
	dialer.LocalAddr = laddr

	conn, err := dialer.Dial(network, raddr.String())
	if err != nil {
		return nil, fmt.Errorf("dialing TCP %s: %w", raddr.String(), err)
	}

	tcpConn, ok := conn.(*Conn).Conn.(*net.TCPConn)
	if !ok {
		if err := conn.Close(); err != nil {
			log.Errorf("Failed to close connection: %v", err)
		}
		return nil, fmt.Errorf("expected TCP connection, got different type: %T", conn)
	}

	return tcpConn, nil
}
