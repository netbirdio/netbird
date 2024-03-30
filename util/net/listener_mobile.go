//go:build android || ios

package net

import (
	"net"
)

func ListenUDP(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	return net.ListenUDP(network, laddr)
}
