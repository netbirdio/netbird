package ws

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	log "github.com/sirupsen/logrus"
	"nhooyr.io/websocket"
)

type Conn struct {
	*websocket.Conn
	lAddr *net.TCPAddr
	rAddr *net.TCPAddr

	ctx context.Context
}

func NewConn(wsConn *websocket.Conn, lAddr, rAddr *net.TCPAddr) *Conn {
	return &Conn{
		Conn:  wsConn,
		lAddr: lAddr,
		rAddr: rAddr,
		ctx:   context.Background(),
	}
}

func (c *Conn) Read(b []byte) (n int, err error) {
	t, r, err := c.Reader(c.ctx)
	if err != nil {
		return 0, ioErrHandling(err)
	}

	if t != websocket.MessageBinary {
		log.Errorf("unexpected message type: %d", t)
		return 0, fmt.Errorf("unexpected message type")
	}

	n, err = r.Read(b)
	if err != nil {
		return 0, ioErrHandling(err)
	}
	return n, err
}

func (c *Conn) Write(b []byte) (int, error) {
	err := c.Conn.Write(c.ctx, websocket.MessageBinary, b)
	return len(b), err
}

func (c *Conn) LocalAddr() net.Addr {
	return c.lAddr
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.rAddr
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
	return nil
}

func (c *Conn) Close() error {
	return c.Conn.Close(websocket.StatusNormalClosure, "")
}

func ioErrHandling(err error) error {
	var wErr *websocket.CloseError
	if !errors.As(err, &wErr) {
		return err
	}
	if wErr.Code == websocket.StatusNormalClosure {
		return io.EOF
	}
	return err
}
