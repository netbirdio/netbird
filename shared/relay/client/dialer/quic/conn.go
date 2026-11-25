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
	netErr "github.com/netbirdio/netbird/shared/relay/client/dialer/net"
)

const (
	Network = "quic"

	writeTimeout = 10 * time.Second
)

type Addr struct {
	addr string
}

func (a Addr) Network() string {
	return Network
}

func (a Addr) String() string {
	return a.addr
}

type Conn struct {
	session *quic.Conn
	ctx     context.Context

	writeMu      sync.Mutex
	writeTimeout time.Duration
	writeTimer   *time.Timer
}

func NewConn(session *quic.Conn) net.Conn {
	c := &Conn{
		session:      session,
		ctx:          context.Background(),
		writeTimeout: writeTimeout,
	}
	c.writeTimer = time.AfterFunc(writeTimeout, c.closeOnWriteTimeout)
	c.writeTimer.Stop()
	return c
}

func (c *Conn) Read(b []byte) (n int, err error) {
	dgram, err := c.session.ReceiveDatagram(c.ctx)
	if err != nil {
		return 0, c.remoteCloseErrHandling(err)
	}

	n = copy(b, dgram)
	return n, nil
}

func (c *Conn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.writeTimer.Reset(c.writeTimeout)
	err := c.session.SendDatagram(b)
	timedOut := !c.writeTimer.Stop()
	if err == nil {
		return len(b), nil
	}
	if timedOut {
		return 0, fmt.Errorf("write timed out after %s: %w", c.writeTimeout, os.ErrDeadlineExceeded)
	}
	return 0, c.writeErrHandling(err, len(b))
}

// Protocol returns the transport name for this connection.
func (c *Conn) Protocol() string {
	return Network
}

// MaxMessageSize returns the largest message a single Write carries.
func (c *Conn) MaxMessageSize() int {
	return nbRelay.QUICMaxDatagramSize
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.session.RemoteAddr()
}

func (c *Conn) LocalAddr() net.Addr {
	if c.session != nil {
		return c.session.LocalAddr()
	}
	return Addr{addr: "unknown"}
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return fmt.Errorf("SetReadDeadline is not implemented")
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return fmt.Errorf("SetWriteDeadline is not implemented")
}

func (c *Conn) SetDeadline(t time.Time) error {
	return nil
}

func (c *Conn) Close() error {
	return c.session.CloseWithError(0, "normal closure")
}

func (c *Conn) remoteCloseErrHandling(err error) error {
	var appErr *quic.ApplicationError
	if errors.As(err, &appErr) && appErr.ErrorCode == 0x0 && appErr.Remote {
		return netErr.ErrClosedByServer
	}
	return err
}

// writeErrHandling normalizes SendDatagram errors. A datagram that exceeds the
// path's QUIC packet budget is mapped to ErrDatagramTooLarge (annotated with the
// datagram size and path budget) so the relay client can fall back to a
// non-datagram transport.
func (c *Conn) writeErrHandling(err error, size int) error {
	var tooLarge *quic.DatagramTooLargeError
	if errors.As(err, &tooLarge) {
		return fmt.Errorf("%w: %d byte datagram over path budget %d", netErr.ErrDatagramTooLarge, size, tooLarge.MaxDatagramPayloadSize)
	}
	return c.remoteCloseErrHandling(err)
}

func (c *Conn) closeOnWriteTimeout() {
	if err := c.session.CloseWithError(0, "write timeout"); err != nil {
		log.Debugf("failed to close relay quic connection after a write timeout: %v", err)
	}
}
