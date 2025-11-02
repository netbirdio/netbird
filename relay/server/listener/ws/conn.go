package ws

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/coder/websocket"
	log "github.com/sirupsen/logrus"
)

const (
	writeTimeout = 10 * time.Second
)

type Conn struct {
	*websocket.Conn
	lAddr *net.TCPAddr
	rAddr *net.TCPAddr

	closed   bool
	closedMu sync.Mutex
	ctx      context.Context
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
		return 0, c.ioErrHandling(err)
	}

	if t != websocket.MessageBinary {
		log.Errorf("unexpected message type: %d", t)
		return 0, fmt.Errorf("unexpected message type")
	}

	n, err = r.Read(b)
	if err != nil {
		return 0, c.ioErrHandling(err)
	}
	return n, err
}

// Write writes a binary message with the given payload.
// It does not block until fill the internal buffer.
// If the buffer filled up, wait until the buffer is drained or timeout.
func (c *Conn) Write(b []byte) (int, error) {
	ctx, ctxCancel := context.WithTimeout(c.ctx, writeTimeout)
	defer ctxCancel()

	err := c.Conn.Write(ctx, websocket.MessageBinary, b)
	return len(b), err
}

func (c *Conn) LocalAddr() net.Addr {
	return c.lAddr
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.rAddr
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
	c.closedMu.Lock()
	c.closed = true
	c.closedMu.Unlock()
	return c.CloseNow()
}

func (c *Conn) isClosed() bool {
	c.closedMu.Lock()
	defer c.closedMu.Unlock()
	return c.closed
}

func (c *Conn) ioErrHandling(err error) error {
	if c.isClosed() {
		return net.ErrClosed
	}

	var wErr *websocket.CloseError
	if !errors.As(err, &wErr) {
		return err
	}
	if wErr.Code == websocket.StatusNormalClosure {
		return net.ErrClosed
	}
	return err
}
