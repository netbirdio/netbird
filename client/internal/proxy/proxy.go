package proxy

import (
	"io"
	"net"
	"time"
)

const DefaultWgKeepAlive = 25 * time.Second

type Proxy interface {
	io.Closer
	// Start creates a local remoteConn and starts proxying data from/to remoteConn
	Start(remoteConn net.Conn) error
}
