package peer

import (
	"io"
	"net"
)

type proxy interface {
	io.Closer
	// Start creates a local remoteConn and starts proxying data from/to remoteConn
	Start(remoteConn net.Conn) error
}
