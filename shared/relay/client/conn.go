package client

import (
	"context"
	"net"
	"time"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

// Conn represent a connection to a relayed remote peer.
type Conn struct {
	dstID       messages.PeerID
	messageChan chan Msg
	instanceURL *RelayAddr
	ctx         context.Context
	writeFn     func(messages.PeerID, []byte) (int, error)
	closeFn     func(messages.PeerID) error
	localAddrFn func() net.Addr
}

// Context returns a context that is cancelled when the connection is torn down,
// either by Close or by the relay client losing the server connection. The
// cancellation cause carries the reason, see ErrServerDisconnected and
// ErrPeerDisconnected.
func (c *Conn) Context() context.Context {
	return c.ctx
}

func (c *Conn) Write(p []byte) (n int, err error) {
	return c.writeFn(c.dstID, p)
}

func (c *Conn) Read(b []byte) (n int, err error) {
	m, ok := <-c.messageChan
	if !ok {
		return 0, net.ErrClosed
	}

	n = copy(b, m.Payload)
	m.Free()
	return n, nil
}

func (c *Conn) Close() error {
	return c.closeFn(c.dstID)
}

func (c *Conn) LocalAddr() net.Addr {
	return c.localAddrFn()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.instanceURL
}

func (c *Conn) SetDeadline(t time.Time) error {
	//TODO implement me
	panic("SetDeadline is not implemented")
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	//TODO implement me
	panic("SetReadDeadline is not implemented")
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	//TODO implement me
	panic("SetReadDeadline is not implemented")
}
