package ws

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/coder/websocket"
)

type Conn struct {
	ctx context.Context
	*websocket.Conn
	remoteAddr net.Addr
}

// NewConn builds a relay ws.Conn. underlying is the raw TCP/TLS conn captured
// from the http transport's DialContext; when set, RemoteAddr returns its
// peer address (an IP literal). When nil (e.g. wasm), RemoteAddr falls back
// to the dial-time URL.
func NewConn(wsConn *websocket.Conn, serverAddress string, underlying net.Conn) net.Conn {
	var addr net.Addr = WebsocketAddr{serverAddress}
	if underlying != nil {
		if ra := underlying.RemoteAddr(); ra != nil {
			addr = ra
		}
	}
	return &Conn{
		ctx:        context.Background(),
		Conn:       wsConn,
		remoteAddr: addr,
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	t, ioReader, err := c.Conn.Reader(c.ctx)
	if err != nil {
		// todo use ErrClosedByServer
		return 0, err
	}

	if t != websocket.MessageBinary {
		return 0, fmt.Errorf("unexpected message type")
	}

	return ioReader.Read(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	return 0, c.Conn.Write(c.ctx, websocket.MessageBinary, b)
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *Conn) LocalAddr() net.Addr {
	return WebsocketAddr{addr: "unknown"}
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return fmt.Errorf("SetReadDeadline is not implemented")
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return fmt.Errorf("SetWriteDeadline is not implemented")
}

func (c *Conn) SetDeadline(t time.Time) error {
	return fmt.Errorf("SetDeadline is not implemented")
}

func (c *Conn) Close() error {
	return c.Conn.CloseNow()
}
