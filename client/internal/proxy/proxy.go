package proxy

import (
	"io"
	"net"
)

type Type string

const (
	TypeDirectNoProxy Type = "DirectNoProxy"
	TypeWireGuard     Type = "WireGuard"
	TypeDummy         Type = "Dummy"
	TypeNoProxy       Type = "NoProxy"
)

type Proxy interface {
	io.Closer
	// Start creates a local remoteConn and starts proxying data from/to remoteConn
	Start(remoteConn net.Conn) error
	Type() Type
}
