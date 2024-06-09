package wsnhooyr

import (
	"context"
	"fmt"
	"net"
	"time"

	"nhooyr.io/websocket"
)

type Conn struct {
	*websocket.Conn
	ctx context.Context
}

func NewConn(wsConn *websocket.Conn) net.Conn {
	return &Conn{
		Conn: wsConn,
		ctx:  context.Background(),
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
	// todo: implement me
	return nil
}

func (c *Conn) LocalAddr() net.Addr {
	// todo: implement me
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	// todo: implement me
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	// todo: implement me
	return nil
}

func (c *Conn) SetDeadline(t time.Time) error {
	// todo: implement me
	errR := c.SetReadDeadline(t)
	errW := c.SetWriteDeadline(t)

	if errR != nil {
		return errR
	}

	if errW != nil {
		return errW
	}
	return nil
}

func (c *Conn) Close() error {
	return c.Conn.CloseNow()
}
