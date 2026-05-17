// Package wt provides the WebTransport server-side wrapper for the relay.
//
// The relay protocol is message-framed and tops out at ~8 KB, well under a
// single QUIC datagram. To preserve the unreliable/unordered semantics that
// raw QUIC offers today (no head-of-line blocking, drops match WireGuard's
// expectations), the WebTransport transport also uses datagrams rather than
// streams.
package wt

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/quic-go/webtransport-go"
)

type Conn struct {
	session  *webtransport.Session
	closed   bool
	closedMu sync.Mutex
}

func NewConn(session *webtransport.Session) *Conn {
	return &Conn{session: session}
}

func (c *Conn) Read(ctx context.Context, b []byte) (int, error) {
	dgram, err := c.session.ReceiveDatagram(ctx)
	if err != nil {
		return 0, c.remoteCloseErrHandling(err)
	}
	return copy(b, dgram), nil
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
	return c.session.CloseWithError(0, "normal closure")
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
	var sessErr *webtransport.SessionError
	if errors.As(err, &sessErr) && sessErr.ErrorCode == 0 {
		return net.ErrClosed
	}
	return err
}
