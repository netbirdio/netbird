package net

import (
	"net"
)

// WrapPacketConn on iOS just returns the original connection since iOS handles its own networking
func WrapPacketConn(conn *net.UDPConn) *net.UDPConn {
	return conn
}
