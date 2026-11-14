// Package keepalive sets the TCP keepalive of a connection that carries an
// aligned heartbeat stream. Clients and servers dial and accept with the stock
// keepalive and switch a connection once its stream is confirmed aligned, so a
// connection without the answer keeps stock behaviour.
package keepalive

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/shared/alignedhb"
)

const (
	// probeInterval is the time between probes once the idle time passed.
	probeInterval = 15 * time.Second
	// probeCount is how many unanswered probes close a dead connection.
	probeCount = 3
)

var (
	// ErrNotTCP reports a connection without a TCP socket below it, such as QUIC
	// or a WebSocket in the browser.
	ErrNotTCP = errors.New("not a TCP connection")

	// conns keeps the aligned streams of each server connection.
	conns = connRegistry{byConn: make(map[*net.TCPConn]*connStreams)}
)

// Stream tunes the keepalive of the connection that carries one server stream.
// Several streams can share a connection, so the connection keeps the aligned
// keepalive until the last of its aligned streams ends. A nil *Stream, for a
// stream whose connection is unknown or not TCP, does nothing.
type Stream struct {
	conn *net.TCPConn

	mu sync.Mutex
	// done is set by Restore: the stream ended, later calls change nothing.
	done bool
}

// netConner is implemented by wrappers that expose the connection below them,
// such as *tls.Conn.
type netConner interface {
	NetConn() net.Conn
}

type connKey struct{}

// connRegistry maps a connection to its aligned streams. Clients reopen a
// stream on the same connection, so an old stream can end after a new one
// switched the connection; per-stream state would then restore stock under the
// new stream.
type connRegistry struct {
	mu     sync.Mutex
	byConn map[*net.TCPConn]*connStreams
}

// connStreams holds the period of each aligned stream on one connection and
// the period whose keepalive the connection has, zero for stock.
type connStreams struct {
	periods map[*Stream]time.Duration
	applied time.Duration
}

// SetAligned sets the keepalive of conn for heartbeats every period: idle for
// alignedhb.TCPKeepAliveIdle(period), then 3 probes 15 s apart.
func SetAligned(conn net.Conn, period time.Duration) error {
	if period <= 0 {
		return fmt.Errorf("period %s", period)
	}
	return set(conn, AlignedConfig(period))
}

// SetStock restores the Go default keepalive of conn.
func SetStock(conn net.Conn) error {
	return set(conn, StockConfig())
}

// AlignedConfig returns the keepalive for a connection with heartbeats every period.
func AlignedConfig(period time.Duration) net.KeepAliveConfig {
	return net.KeepAliveConfig{
		Enable:   true,
		Idle:     alignedhb.TCPKeepAliveIdle(period),
		Interval: probeInterval,
		Count:    probeCount,
	}
}

// StockConfig returns the Go default keepalive that dialers and listeners use
// when KeepAlive is zero.
func StockConfig() net.KeepAliveConfig {
	return net.KeepAliveConfig{Enable: true}
}

// TCPConn returns the TCP connection below conn, unwrapping layers that
// implement NetConn.
func TCPConn(conn net.Conn) (*net.TCPConn, bool) {
	for conn != nil {
		switch c := conn.(type) {
		case *net.TCPConn:
			return c, true
		case netConner:
			conn = c.NetConn()
		default:
			return nil, false
		}
	}
	return nil, false
}

// ConnContext is an http.Server ConnContext that keeps the accepted connection
// in the context of its requests. gRPC served through ServeHTTP passes that
// context to its streams, so a stream handler can tune its connection.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, c)
}

// ConnFromContext returns the connection stored by ConnContext.
func ConnFromContext(ctx context.Context) (net.Conn, bool) {
	c, ok := ctx.Value(connKey{}).(net.Conn)
	return c, ok && c != nil
}

// ForStream returns the tuner for the connection of the stream with context
// ctx, nil when the server did not store the connection (ConnContext) or the
// connection is not TCP.
func ForStream(ctx context.Context) *Stream {
	c, ok := ConnFromContext(ctx)
	if !ok {
		return nil
	}
	tc, ok := TCPConn(c)
	if !ok {
		return nil
	}
	return &Stream{conn: tc}
}

// SetAligned marks the stream aligned with heartbeats every period and switches
// the connection to the keepalive of the longest period among its aligned
// streams.
func (s *Stream) SetAligned(period time.Duration) {
	if s == nil || period <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return
	}
	conns.update(s.conn, s, period)
}

// Restore ends the stream and ignores later SetAligned calls. The connection
// goes back to the stock keepalive when no aligned stream is left on it, since
// gRPC can reuse it for a stock stream. Every stream that called SetAligned
// must call Restore when it ends.
func (s *Stream) Restore() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done {
		return
	}
	s.done = true
	conns.update(s.conn, s, 0)
}

func set(conn net.Conn, cfg net.KeepAliveConfig) error {
	tc, ok := TCPConn(conn)
	if !ok {
		return ErrNotTCP
	}
	if err := tc.SetKeepAliveConfig(cfg); err != nil {
		return fmt.Errorf("set keepalive: %w", err)
	}
	return nil
}

// update sets the period of stream s on conn, zero when s ended, and applies the
// keepalive of the longest period left. A connection without aligned streams is
// dropped from the registry.
func (r *connRegistry) update(conn *net.TCPConn, s *Stream, period time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	cs := r.byConn[conn]
	if cs == nil {
		if period <= 0 {
			return
		}
		cs = &connStreams{periods: make(map[*Stream]time.Duration)}
		r.byConn[conn] = cs
	}
	if period > 0 {
		cs.periods[s] = period
	} else {
		delete(cs.periods, s)
	}
	if len(cs.periods) == 0 {
		delete(r.byConn, conn)
	}
	cs.apply(conn)
}

// apply switches conn to the keepalive of the longest period of its streams, or
// to stock when none is left. A failed switch is retried on the next update.
func (cs *connStreams) apply(conn *net.TCPConn) {
	var want time.Duration
	for _, p := range cs.periods {
		want = max(want, p)
	}
	if want == cs.applied {
		return
	}
	if want == 0 {
		if err := SetStock(conn); err != nil {
			log.Debugf("failed to restore the stock TCP keepalive: %v", err)
		}
		cs.applied = 0
		return
	}
	if err := SetAligned(conn, want); err != nil {
		log.Debugf("failed to set TCP keepalive for heartbeat period %s: %v", want, err)
		return
	}
	cs.applied = want
}
