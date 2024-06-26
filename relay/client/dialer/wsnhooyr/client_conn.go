package wsnhooyr

import (
	"context"
	"fmt"
	"net"
	"time"

	"nhooyr.io/websocket"
)

type Conn struct {
	ctx context.Context
	*websocket.Conn
	srvAddr *net.TCPAddr
}

func NewConn(wsConn *websocket.Conn, srvAddr *net.TCPAddr) net.Conn {
	return &Conn{
		ctx:     context.Background(),
		Conn:    wsConn,
		srvAddr: srvAddr,
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	t, ioReader, err := c.Conn.Reader(c.ctx)
	if err != nil {
		return 0, err
	}

	if t != websocket.MessageBinary {
		return 0, fmt.Errorf("unexpected message type")
	}

	return ioReader.Read(b)
}

func (c *Conn) Write(b []byte) (n int, err error) {
	err = c.Conn.Write(c.ctx, websocket.MessageBinary, b)
	return len(b), err
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.srvAddr
}

func (c *Conn) LocalAddr() net.Addr {
	// todo: implement me
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return fmt.Errorf("not implemented")
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return fmt.Errorf("not implemented")
}

func (c *Conn) SetDeadline(t time.Time) error {
	return fmt.Errorf("not implemented")
}

func (c *Conn) Close() error {
	return c.Conn.CloseNow()
}
