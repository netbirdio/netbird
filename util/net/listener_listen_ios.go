package net

import (
	"net"
)

// WrapUDPConn on iOS just returns the original connection since iOS handles its own networking
func WrapUDPConn(conn *net.UDPConn) *net.UDPConn {
	return conn
}
