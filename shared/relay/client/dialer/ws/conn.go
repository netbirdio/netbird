package ws

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/coder/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/relay/messages"
)

const writeTimeout = 10 * time.Second

type Conn struct {
	ctx context.Context
	*websocket.Conn
	remoteAddr net.Addr

	writeMu      sync.Mutex
	writeTimeout time.Duration
	writeTimer   *time.Timer
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
	c := &Conn{
		ctx:          context.Background(),
		Conn:         wsConn,
		remoteAddr:   addr,
		writeTimeout: writeTimeout,
	}
	c.writeTimer = time.AfterFunc(writeTimeout, c.closeOnWriteTimeout)
	c.writeTimer.Stop()
	return c
}

// Protocol returns the transport name for this connection.
func (c *Conn) Protocol() string {
	return Network
}

// MaxMessageSize returns the largest message a single Write carries.
func (c *Conn) MaxMessageSize() int {
	return messages.MaxMessageSize
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
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.writeTimer.Reset(c.writeTimeout)
	err = c.Conn.Write(c.ctx, websocket.MessageBinary, b)
	if !c.writeTimer.Stop() && err != nil {
		return 0, fmt.Errorf("write timed out after %s: %w", c.writeTimeout, os.ErrDeadlineExceeded)
	}
	return 0, err
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
	return c.closeConn()
}

func (c *Conn) closeOnWriteTimeout() {
	if err := c.closeConn(); err != nil {
		log.Debugf("failed to close relay websocket after a write timeout: %v", err)
	}
}
