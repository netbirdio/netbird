// Package keepalive sets the TCP keepalive of a connection that carries an
// aligned heartbeat stream. Servers accept with the stock keepalive and switch
// a connection once at its first aligned stream, adding TCP_USER_TIMEOUT on
// Linux, and never restore it: a connection that later carried a stock stream
// would keep the aligned idle until it closes, which the current client never
// opens. Clients set only the keepalive on their own sockets.
//
// The switch is idempotent, so there is no registry of streams per
// connection and nothing to undo when a stream ends.
package keepalive

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/netbirdio/netbird/shared/alignedhb"
)

const (
	// probeInterval is the time between probes once the idle time passed.
	probeInterval = 15 * time.Second
	// probeCount is how many unanswered probes close a dead connection.
	probeCount = 3
	// userTimeoutMargin is added past the keepalive idle time for
	// TCP_USER_TIMEOUT, so a live but slow connection is not cut.
	userTimeoutMargin = 30 * time.Second
)

var (
	// ErrNotTCP reports a connection without a TCP socket below it, such as
	// QUIC or a WebSocket.
	ErrNotTCP = errors.New("not a TCP connection")
	// ErrNoConn reports a stream context without a stored connection. The
	// server did not wire ConnContext, so the stream keeps stock behaviour.
	ErrNoConn = errors.New("no connection in stream context")
)

// netConner is implemented by wrappers that expose the connection below them,
// such as *tls.Conn.
type netConner interface {
	NetConn() net.Conn
}

type connKey struct{}

// AlignedConfig returns the keepalive for a connection with heartbeats every
// period: idle for alignedhb.TCPKeepAliveIdle(period), then 3 probes 15 s
// apart.
func AlignedConfig(period time.Duration) net.KeepAliveConfig {
	return net.KeepAliveConfig{
		Enable:   true,
		Idle:     alignedhb.TCPKeepAliveIdle(period),
		Interval: probeInterval,
		Count:    probeCount,
	}
}

// UserTimeout returns the TCP_USER_TIMEOUT for a connection with heartbeats
// every period: 2 periods plus 30 s. A vanished peer is dropped after about
// this long even though its unacked heartbeats block the TCP keepalive.
func UserTimeout(period time.Duration) time.Duration {
	return alignedhb.TCPKeepAliveIdle(period) + userTimeoutMargin
}

// SetAligned sets the keepalive of conn for heartbeats every period. It
// leaves TCP_USER_TIMEOUT alone, so clients can use it on their own sockets.
// Calling it again with the same period changes nothing.
func SetAligned(conn net.Conn, period time.Duration) error {
	if period <= 0 {
		return fmt.Errorf("invalid period %s", period)
	}
	tc, ok := TCPConn(conn)
	if !ok {
		return ErrNotTCP
	}
	if err := tc.SetKeepAliveConfig(AlignedConfig(period)); err != nil {
		return fmt.Errorf("set keepalive: %w", err)
	}
	return nil
}

// SetAlignedStream sets the connection of the server stream with context ctx,
// stored there by ConnContext, for heartbeats every period: the keepalive of
// SetAligned and, on Linux, TCP_USER_TIMEOUT of UserTimeout(period). Servers
// call it once, at the first aligned stream of a connection. A server whose
// listener did not store the connection gets ErrNoConn and keeps stock
// behaviour.
func SetAlignedStream(ctx context.Context, period time.Duration) error {
	conn, ok := ConnFromContext(ctx)
	if !ok {
		return ErrNoConn
	}
	if err := SetAligned(conn, period); err != nil {
		return err
	}
	tc, _ := TCPConn(conn)
	if err := setUserTimeout(tc, UserTimeout(period)); err != nil {
		return fmt.Errorf("set user timeout: %w", err)
	}
	return nil
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

// ConnContext is an http.Server ConnContext that keeps the accepted
// connection in the context of its requests. gRPC served through ServeHTTP
// passes that context to its streams, so a stream handler can tune its
// connection.
func ConnContext(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connKey{}, c)
}

// ConnFromContext returns the connection stored by ConnContext.
func ConnFromContext(ctx context.Context) (net.Conn, bool) {
	if ctx == nil {
		return nil, false
	}
	c, ok := ctx.Value(connKey{}).(net.Conn)
	return c, ok && c != nil
}
