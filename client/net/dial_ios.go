package net

import (
	"net"
)

func DialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	return net.DialUDP(network, laddr, raddr)
}

func DialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	return net.DialTCP(network, laddr, raddr)
}
