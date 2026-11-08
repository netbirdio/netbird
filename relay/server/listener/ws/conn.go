package ws

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/testhb"
)

const (
	writeTimeout = 10 * time.Second
)

type Conn struct {
	*websocket.Conn
	rAddr *net.TCPAddr

	closed   bool
	closedMu sync.Mutex

	// hbSchedule is the test heartbeat schedule the client sent in the URL.
	hbSchedule testhb.ClientSchedule
}

func NewConn(wsConn *websocket.Conn, rAddr *net.TCPAddr) *Conn {
	return &Conn{
		Conn:  wsConn,
		rAddr: rAddr,
	}
}

// TestHBSchedule returns the test heartbeat schedule the client sent in the URL.
func (c *Conn) TestHBSchedule() testhb.ClientSchedule {
	return c.hbSchedule
}

// SetTestHBScheduleFromRequest reads the test heartbeat schedule from the
// upgrade request. For handlers outside Listener, such as the combined server.
// arrival is the wall time when the upgrade request arrived.
func (c *Conn) SetTestHBScheduleFromRequest(r *http.Request, arrival time.Time) {
	c.hbSchedule = testHBClientSchedule(r, arrival)
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
