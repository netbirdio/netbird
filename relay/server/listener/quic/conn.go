package quic

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
)

type Conn struct {
	session  *quic.Conn
	closed   bool
	closedMu sync.Mutex
}

func NewConn(session *quic.Conn) *Conn {
	return &Conn{
		session: session,
	}
}

func (c *Conn) Read(ctx context.Context, b []byte) (n int, err error) {
	dgram, err := c.session.ReceiveDatagram(ctx)
	if err != nil {
		return 0, c.remoteCloseErrHandling(err)
	}
	// Copy data to b, ensuring we don’t exceed the size of b
	n = copy(b, dgram)
	return n, nil
}

func (c *Conn) Write(_ context.Context, b []byte) (int, error) {
	if err := c.session.SendDatagram(b); err != nil {
		return 0, c.remoteCloseErrHandling(err)
	}
	return len(b), nil
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.session.RemoteAddr()
}

func (c *Conn) Close() error {
	c.closedMu.Lock()
	if c.closed {
		c.closedMu.Unlock()
		return nil
	}
	c.closed = true
	c.closedMu.Unlock()

	sessionErr := c.session.CloseWithError(0, "normal closure")
	return sessionErr
}

func (c *Conn) isClosed() bool {
	c.closedMu.Lock()
	defer c.closedMu.Unlock()
	return c.closed
}

func (c *Conn) remoteCloseErrHandling(err error) error {
	if c.isClosed() {
		return net.ErrClosed
	}

	// Check if the connection was closed remotely
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) && appErr.ErrorCode == 0x0 {
		return net.ErrClosed
	}

	return err
}
