package wgproxy

import (
	"net"
)

// Proxy is a transfer layer between the Turn connection and the WireGuard
type Proxy interface {
	AddTurnConn(turnConn net.Conn) (net.Addr, error)
	CloseConn() error
	Free() error
}
