package activity

import (
	"context"
	"io"
	"net"
	"slices"
	"sync"
	"time"
)

// lazyConn detects activity when WireGuard attempts to send packets.
// It does not deliver packets, only signals that activity occurred. The first packet WG-go writes
// is captured so the lazyconn manager can reinject it through the real bind endpoint, avoiding the
// handshake-retry wait when the real connection comes up.
type lazyConn struct {
	activityCh chan struct{}
	ctx        context.Context
	cancel     context.CancelFunc

	mu             sync.Mutex
	capturedPacket []byte
}

// newLazyConn creates a new lazyConn for activity detection.
func newLazyConn() *lazyConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &lazyConn{
		activityCh: make(chan struct{}, 1),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Read blocks until the connection is closed.
func (c *lazyConn) Read(_ []byte) (n int, err error) {
	<-c.ctx.Done()
	return 0, io.EOF
}

// Write signals activity detection when ICEBind routes packets to this endpoint. The first packet
// is cloned and stored so it can be replayed on the real endpoint once ICE/relay comes up.
func (c *lazyConn) Write(b []byte) (n int, err error) {
	if c.ctx.Err() != nil {
		return 0, io.EOF
	}

	c.mu.Lock()
	if c.capturedPacket == nil && len(b) > 0 {
		c.capturedPacket = slices.Clone(b)
	}
	c.mu.Unlock()

	select {
	case c.activityCh <- struct{}{}:
	default:
	}

	return len(b), nil
}

// CapturedPacket returns the first packet written to this connection, or nil. The slice aliases
// the internal buffer, which is written once and never mutated, so the caller must not modify it.
func (c *lazyConn) CapturedPacket() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.capturedPacket
}

// ActivityChan returns the channel that signals when activity is detected.
func (c *lazyConn) ActivityChan() <-chan struct{} {
	return c.activityCh
}

// Close closes the connection.
func (c *lazyConn) Close() error {
	c.cancel()
	return nil
}

// LocalAddr returns the local address.
func (c *lazyConn) LocalAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: lazyBindPort}
}

// RemoteAddr returns the remote address.
func (c *lazyConn) RemoteAddr() net.Addr {
	return &net.UDPAddr{IP: net.IP{127, 0, 0, 1}, Port: lazyBindPort}
}

// SetDeadline sets the read and write deadlines.
func (c *lazyConn) SetDeadline(_ time.Time) error {
	return nil
}

// SetReadDeadline sets the deadline for future Read calls.
func (c *lazyConn) SetReadDeadline(_ time.Time) error {
	return nil
}

// SetWriteDeadline sets the deadline for future Write calls.
func (c *lazyConn) SetWriteDeadline(_ time.Time) error {
	return nil
}
