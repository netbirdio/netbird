package tcp

import (
	"bytes"
	"io"
	"net"
)

// peekedConn wraps a net.Conn and prepends previously peeked bytes
// so that readers see the full original stream transparently.
type peekedConn struct {
	net.Conn
	reader io.Reader
}

func newPeekedConn(conn net.Conn, peeked []byte) *peekedConn {
	return &peekedConn{
		Conn:   conn,
		reader: io.MultiReader(bytes.NewReader(peeked), conn),
	}
}

// Read replays the peeked bytes first, then reads from the underlying conn.
func (c *peekedConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// halfCloser matches connections that support shutting down the write
// side while keeping the read side open (e.g. *net.TCPConn).
type halfCloser interface {
	CloseWrite() error
}

// CloseWrite delegates to the underlying connection if it supports
// half-close (e.g. *net.TCPConn). Without this, embedding net.Conn
// as an interface hides the concrete type's CloseWrite method, making
// half-close a silent no-op for all SNI-routed connections.
func (c *peekedConn) CloseWrite() error {
	if hc, ok := c.Conn.(halfCloser); ok {
		return hc.CloseWrite()
	}
	return nil
}

var _ halfCloser = (*peekedConn)(nil)
