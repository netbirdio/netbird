//go:build !linux

package net

import (
	"net"
)

func NewDialer() *net.Dialer {
	return &net.Dialer{}
}

func DialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	return net.DialUDP(network, laddr, raddr)
}

func DialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	return net.DialTCP(network, laddr, raddr)
}
