package wgproxy

import (
	"io"
	"net"
)

// Proxy definition
type Proxy interface {
	AddTurnConn(urnConn net.Conn) (net.Addr, error)
	io.Closer
}
