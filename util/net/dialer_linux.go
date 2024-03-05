//go:build !android

package net

import (
	"context"
	"fmt"
	"net"
	"syscall"

	log "github.com/sirupsen/logrus"
)

func NewDialer() *net.Dialer {
	return &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return SetRawSocketMark(c)
		},
	}
}

func DialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	dialer := NewDialer()
	dialer.LocalAddr = laddr

	conn, err := dialer.DialContext(context.Background(), network, raddr.String())
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

	conn, err := dialer.DialContext(context.Background(), network, raddr.String())
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
