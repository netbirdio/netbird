package types

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceMode_IsL4(t *testing.T) {
	tests := []struct {
		mode ServiceMode
		want bool
	}{
		{ServiceModeHTTP, false},
		{ServiceModeTCP, true},
		{ServiceModeUDP, true},
		{ServiceModeTLS, true},
		{ServiceMode("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			assert.Equal(t, tt.want, tt.mode.IsL4())
		})
	}
}

func TestDialTimeoutContext(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		ctx := WithDialTimeout(context.Background(), 5*time.Second)
		d, ok := DialTimeoutFromContext(ctx)
		assert.True(t, ok)
		assert.Equal(t, 5*time.Second, d)
	})

	t.Run("missing", func(t *testing.T) {
		_, ok := DialTimeoutFromContext(context.Background())
		assert.False(t, ok)
	})

	t.Run("zero returns false", func(t *testing.T) {
		ctx := WithDialTimeout(context.Background(), 0)
		_, ok := DialTimeoutFromContext(ctx)
		assert.False(t, ok, "zero duration should return ok=false")
	})

	t.Run("negative returns false", func(t *testing.T) {
		ctx := WithDialTimeout(context.Background(), -1*time.Second)
		_, ok := DialTimeoutFromContext(ctx)
		assert.False(t, ok, "negative duration should return ok=false")
	})
}

type stubAddr struct{ s string }

func (a stubAddr) Network() string { return "tcp" }
func (a stubAddr) String() string  { return a.s }

type stubConn struct {
	remote net.Addr
}

func (c stubConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c stubConn) Write([]byte) (int, error)        { return 0, io.EOF }
func (c stubConn) Close() error                     { return nil }
func (c stubConn) LocalAddr() net.Addr              { return stubAddr{s: "10.0.0.1:1"} }
func (c stubConn) RemoteAddr() net.Addr             { return c.remote }
func (c stubConn) SetDeadline(time.Time) error      { return nil }
func (c stubConn) SetReadDeadline(time.Time) error  { return nil }
func (c stubConn) SetWriteDeadline(time.Time) error { return nil }

func TestGuardLoopbackDial(t *testing.T) {
	t.Run("literal loopback", func(t *testing.T) {
		called := false
		dial := GuardLoopbackDial(func(context.Context, string, string) (net.Conn, error) {
			called = true
			return stubConn{}, nil
		})
		_, err := dial(context.Background(), "tcp", "127.0.0.1:8080")
		assert.ErrorIs(t, err, ErrLoopbackTarget)
		assert.False(t, called, "literal loopback must be rejected before dialing")
	})

	t.Run("literal ipv6 loopback", func(t *testing.T) {
		called := false
		dial := GuardLoopbackDial(func(context.Context, string, string) (net.Conn, error) {
			called = true
			return stubConn{}, nil
		})
		_, err := dial(context.Background(), "tcp", "[::1]:8080")
		assert.ErrorIs(t, err, ErrLoopbackTarget)
		assert.False(t, called, "literal IPv6 loopback must be rejected before dialing")
	})

	t.Run("mapped ipv6 loopback", func(t *testing.T) {
		called := false
		dial := GuardLoopbackDial(func(context.Context, string, string) (net.Conn, error) {
			called = true
			return stubConn{}, nil
		})
		_, err := dial(context.Background(), "tcp", "[::ffff:127.0.0.1]:8080")
		assert.ErrorIs(t, err, ErrLoopbackTarget)
		assert.False(t, called, "mapped IPv6 loopback must be rejected before dialing")
	})

	t.Run("localhost name", func(t *testing.T) {
		called := false
		dial := GuardLoopbackDial(func(context.Context, string, string) (net.Conn, error) {
			called = true
			return stubConn{}, nil
		})
		_, err := dial(context.Background(), "tcp", "localhost.:8080")
		assert.ErrorIs(t, err, ErrLoopbackTarget)
		assert.False(t, called, "localhost forms must be rejected before dialing")
	})

	t.Run("resolved loopback", func(t *testing.T) {
		dial := GuardLoopbackDial(func(context.Context, string, string) (net.Conn, error) {
			return stubConn{remote: stubAddr{s: "127.0.0.1:8080"}}, nil
		})
		_, err := dial(context.Background(), "tcp", "evil.example:8080")
		assert.ErrorIs(t, err, ErrLoopbackTarget)
	})

	t.Run("overlay address allowed", func(t *testing.T) {
		dial := GuardLoopbackDial(func(context.Context, string, string) (net.Conn, error) {
			return stubConn{remote: stubAddr{s: "100.64.0.1:8080"}}, nil
		})
		conn, err := dial(context.Background(), "tcp", "100.64.0.1:8080")
		require.NoError(t, err)
		assert.Equal(t, "100.64.0.1:8080", conn.RemoteAddr().String())
	})
}
