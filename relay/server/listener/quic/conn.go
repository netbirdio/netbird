package quic

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	log "github.com/sirupsen/logrus"

	nbRelay "github.com/netbirdio/netbird/shared/relay"
)

const writeTimeout = 10 * time.Second

type Conn struct {
	session  *quic.Conn
	closed   bool
	closedMu sync.Mutex

	writeMu    sync.Mutex
	writeTimer *time.Timer
}

func NewConn(session *quic.Conn) *Conn {
	c := &Conn{
		session: session,
	}
	c.writeTimer = time.AfterFunc(writeTimeout, c.closeOnWriteTimeout)
	c.writeTimer.Stop()
	return c
}

func (c *Conn) Read(ctx context.Context, b []byte) (n int, err error) {
	dgram, err := c.session.ReceiveDatagram(ctx)
	if err != nil {
		return 0, c.remoteCloseErrHandling(err)
	}
	// Copy data to b, ensuring we don’t exceed the size of b
	n = copy(b, dgram)
	return n, nil
}

func (c *Conn) Write(ctx context.Context, b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	timeout := writeTimeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(deadline))
	}

	c.writeTimer.Reset(timeout)
	err := c.session.SendDatagram(b)
	timedOut := !c.writeTimer.Stop()
	if err == nil {
		return len(b), nil
	}
	if timedOut {
		return 0, fmt.Errorf("write timed out after %s: %w", timeout, os.ErrDeadlineExceeded)
	}
	return 0, c.remoteCloseErrHandling(err)
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.session.RemoteAddr()
}

// Protocol returns the transport name for this connection.
func (c *Conn) Protocol() string {
	return "quic"
}

// MaxMessageSize returns the largest message a single Write carries.
func (c *Conn) MaxMessageSize() int {
	return nbRelay.QUICMaxDatagramSize
}

func (c *Conn) Close() error {
	c.closedMu.Lock()
	if c.closed {
		c.closedMu.Unlock()
		return nil
	}
	c.closed = true
	c.closedMu.Unlock()

	sessionErr := c.session.CloseWithError(0, "normal closure")
	return sessionErr
}

func (c *Conn) isClosed() bool {
	c.closedMu.Lock()
	defer c.closedMu.Unlock()
	return c.closed
}

func (c *Conn) remoteCloseErrHandling(err error) error {
	if c.isClosed() {
		return net.ErrClosed
	}

	// Check if the connection was closed remotely
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) && appErr.ErrorCode == 0x0 {
		return net.ErrClosed
	}

	return err
}

func (c *Conn) closeOnWriteTimeout() {
	if err := c.session.CloseWithError(0, "write timeout"); err != nil {
		log.Debugf("failed to close quic connection after a write timeout: %v", err)
	}
}
