package quic

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

type QuicAddr struct {
	addr string
}

func (a QuicAddr) Network() string {
	return "quic"
}

func (a QuicAddr) String() string {
	return a.addr
}

type Conn struct {
	session    quic.Connection
	remoteAddr QuicAddr
	ctx        context.Context
}

func NewConn(session quic.Connection, serverAddress string) net.Conn {
	return &Conn{
		session:    session,
		remoteAddr: QuicAddr{addr: serverAddress},
		ctx:        context.Background(),
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	// Use the QUIC stream's Read method directly
	dgram, err := c.session.ReceiveDatagram(c.ctx)
	if err != nil {
		return 0, fmt.Errorf("failed to read from QUIC stream: %v", err)
	}

	// Copy data to b, ensuring we don’t exceed the size of b
	n = copy(b, dgram)
	return n, nil
}

func (c *Conn) Write(b []byte) (int, error) {
	// Use the QUIC stream's Write method directly
	err := c.session.SendDatagram(b)
	if err != nil {
		return 0, fmt.Errorf("failed to write to QUIC stream: %v", err)
	}
	return len(b), nil
}

func (c *Conn) RemoteAddr() net.Addr {
	if c.session != nil {
		return c.session.RemoteAddr()
	}
	return c.remoteAddr
}

func (c *Conn) LocalAddr() net.Addr {
	if c.session != nil {
		return c.session.LocalAddr()
	}
	return QuicAddr{addr: "unknown"}
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *Conn) SetDeadline(t time.Time) error {

	return nil
}

func (c *Conn) Close() error {
	return c.session.CloseWithError(0, "normal closure")
}
