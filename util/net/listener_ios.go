//go:build ios

package net

import (
	"net"
)

func (l *ListenerConfig) init() {
}

func ListenUDP(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	return net.ListenUDP(network, laddr)
}
