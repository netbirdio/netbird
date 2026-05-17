//go:build js

package wt

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall/js"
	"time"

	netErr "github.com/netbirdio/netbird/shared/relay/client/dialer/net"
)

// addr satisfies net.Addr for the WebTransport-backed conn. The remote address
// is opaque (the browser doesn't expose the underlying UDP 4-tuple), so we
// surface the dial URL instead.
type addr struct{ s string }

func (a addr) Network() string { return Network }
func (a addr) String() string  { return a.s }

// conn wraps a WebTransport session and implements net.Conn over its datagram
// channels. Each Read consumes exactly one inbound datagram (= one relay
// message); each Write transmits exactly one (= one relay message). This
// preserves the message-boundary semantics the relay framing assumes.
type conn struct {
	wt     js.Value
	writer js.Value // datagrams.writable.getWriter()
	reader js.Value // datagrams.readable.getReader()

	ctx    context.Context
	cancel context.CancelFunc

	closeOnce sync.Once
	closed    chan struct{}

	remote addr
}

func newConn(wt js.Value, dialURL string) *conn {
	ctx, cancel := context.WithCancel(context.Background())
	c := &conn{
		wt:     wt,
		writer: wt.Get("datagrams").Get("writable").Call("getWriter"),
		reader: wt.Get("datagrams").Get("readable").Call("getReader"),
		ctx:    ctx,
		cancel: cancel,
		closed: make(chan struct{}),
		remote: addr{s: dialURL},
	}
	// Best-effort close detection: when the session closes, surface it as
	// net.ErrClosed on subsequent ops.
	go c.watchClosed()
	return c
}

func (c *conn) watchClosed() {
	closedP := c.wt.Get("closed")
	if !closedP.Truthy() {
		return
	}
	_, _ = awaitPromise(c.ctx, closedP)
	c.markClosed()
}

func (c *conn) Read(b []byte) (int, error) {
	for {
		select {
		case <-c.closed:
			return 0, net.ErrClosed
		default:
		}
		readP := c.reader.Call("read")
		v, err := awaitPromise(c.ctx, readP)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return 0, net.ErrClosed
			}
			return 0, netErr.ErrClosedByServer
		}
		if v.Get("done").Bool() {
			c.markClosed()
			return 0, io.EOF
		}
		val := v.Get("value")
		if !val.Truthy() {
			continue
		}
		n := val.Get("byteLength").Int()
		if n > len(b) {
			// Datagrams shouldn't exceed the relay's MaxMessageSize (8 KB) so
			// this branch is defensive — truncate rather than fail hard.
			n = len(b)
		}
		js.CopyBytesToGo(b[:n], val)
		return n, nil
	}
}

func (c *conn) Write(b []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	u8 := js.Global().Get("Uint8Array").New(len(b))
	js.CopyBytesToJS(u8, b)
	writeP := c.writer.Call("write", u8)
	if _, err := awaitPromise(c.ctx, writeP); err != nil {
		if errors.Is(err, context.Canceled) {
			return 0, net.ErrClosed
		}
		return 0, netErr.ErrClosedByServer
	}
	return len(b), nil
}

func (c *conn) Close() error {
	c.markClosed()
	_ = safeCall(c.wt, "close")
	return nil
}

func (c *conn) markClosed() {
	c.closeOnce.Do(func() {
		c.cancel()
		close(c.closed)
	})
}

func (c *conn) LocalAddr() net.Addr  { return addr{s: "wasm"} }
func (c *conn) RemoteAddr() net.Addr { return c.remote }

func (c *conn) SetDeadline(time.Time) error      { return nil }
func (c *conn) SetReadDeadline(time.Time) error  { return fmt.Errorf("SetReadDeadline not implemented") }
func (c *conn) SetWriteDeadline(time.Time) error { return fmt.Errorf("SetWriteDeadline not implemented") }
