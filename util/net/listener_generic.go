//go:build !linux

package net

import "net"

func NewListener() *net.ListenConfig {
	return &net.ListenConfig{}
}

func ListenUDP(network string, locAddr *net.UDPAddr) (*net.UDPConn, error) {
	return net.ListenUDP(network, locAddr)
}
