package wgproxy

import (
	"net"
)

// Proxy definition
type Proxy interface {
	AddTurnConn(urnConn net.Conn) (net.Addr, error)
	CloseConn() error
	Free() error
}
