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

	"github.com/netbirdio/netbird/shared/alignedhb/keepalive"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

const (
	writeTimeout = 10 * time.Second
)

type Conn struct {
	*websocket.Conn
	rAddr *net.TCPAddr
	// netConn is the accepted connection under the WebSocket, nil when unknown.
	netConn net.Conn

	closed   bool
	closedMu sync.Mutex
}

func NewConn(wsConn *websocket.Conn, rAddr *net.TCPAddr, netConn net.Conn) *Conn {
	return &Conn{
		Conn:    wsConn,
		rAddr:   rAddr,
		netConn: netConn,
	}
}

// UseAlignedHeartbeat sets the socket keepalive for an aligned heartbeat client
// with heartbeats every period, with the rule Management and Signal use, so no
// probe wakes the client between two heartbeats. The kernel keeps the stock
// tolerance for unacknowledged data, so a client without radio for a while
// keeps its connection. The healthcheck sender closes a client that misses the
// heartbeat ack.
func (c *Conn) UseAlignedHeartbeat(period time.Duration) error {
	return keepalive.SetAligned(c.netConn, period)
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
	ctx, ctxCancel := context.WithTimeout(ctx, writeTimeout)
	defer ctxCancel()

	err := c.Conn.Write(ctx, websocket.MessageBinary, b)
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
