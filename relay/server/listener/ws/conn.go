package ws

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/coder/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	writeTimeout = 10 * time.Second
)

type Conn struct {
	*websocket.Conn
	rAddr *net.TCPAddr

	closed   bool
	closedMu sync.Mutex

	writeMu    sync.Mutex
	writeTimer *time.Timer
}

func NewConn(wsConn *websocket.Conn, rAddr *net.TCPAddr) *Conn {
	c := &Conn{
		Conn:  wsConn,
		rAddr: rAddr,
	}
	c.writeTimer = time.AfterFunc(writeTimeout, c.closeOnWriteTimeout)
	c.writeTimer.Stop()
	return c
}

func (c *Conn) Read(ctx context.Context, b []byte) (n int, err error) {
	t, r, err := c.Reader(ctx)
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
func (c *Conn) Write(ctx context.Context, b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.writeTimer.Reset(writeTimeout)
	err := c.Conn.Write(ctx, websocket.MessageBinary, b)
	if !c.writeTimer.Stop() && err != nil {
		err = fmt.Errorf("write timed out after %s: %w", writeTimeout, os.ErrDeadlineExceeded)
	}
	return len(b), err
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.rAddr
}

// Protocol returns the transport name for this connection.
func (c *Conn) Protocol() string {
	return "ws"
}

// MaxMessageSize returns the largest message a single Write carries.
func (c *Conn) MaxMessageSize() int {
	return messages.MaxMessageSize
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

func (c *Conn) closeOnWriteTimeout() {
	if err := c.Close(); err != nil {
		log.Debugf("failed to close websocket after a write timeout: %v", err)
	}
}
