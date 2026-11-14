package keepalive

import (
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	s, ok := <-accepted
	require.True(t, ok, "accept must succeed")
	t.Cleanup(func() { _ = s.Close() })
	return c.(*net.TCPConn), s.(*net.TCPConn)
}

type wrapped struct {
	net.Conn
}

func (w wrapped) NetConn() net.Conn { return w.Conn }

func TestTCPConnUnwraps(t *testing.T) {
	c, _ := tcpPair(t)

	got, ok := TCPConn(c)
	assert.True(t, ok, "plain TCP connection")
	assert.Same(t, c, got)

	got, ok = TCPConn(tls.Client(wrapped{c}, &tls.Config{}))
	assert.True(t, ok, "TLS over a wrapper")
	assert.Same(t, c, got)

	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	_, ok = TCPConn(p1)
	assert.False(t, ok, "a pipe has no TCP socket")
	_, ok = TCPConn(wrapped{})
	assert.False(t, ok, "a wrapper without a connection")
	_, ok = TCPConn(nil)
	assert.False(t, ok, "nil")
}

func skipWithoutIdle(t *testing.T) {
	t.Helper()
	if _, err := Idle(nil); errors.Is(err, errors.ErrUnsupported) {
		t.Skip(err)
	}
}

func TestSetAlignedAndStock(t *testing.T) {
	skipWithoutIdle(t)
	c, s := tcpPair(t)

	require.NoError(t, SetAligned(wrapped{c}, time.Minute))
	idle, err := Idle(c)
	require.NoError(t, err)
	assert.Equal(t, 2*time.Minute, idle, "aligned idle at a 60 s period")

	require.NoError(t, SetAligned(s, 90*time.Second))
	idle, err = Idle(s)
	require.NoError(t, err)
	assert.Equal(t, 3*time.Minute, idle, "server end at a 90 s period")

	require.NoError(t, SetStock(c))
	idle, err = Idle(c)
	require.NoError(t, err)
	assert.Equal(t, 15*time.Second, idle, "stock is the Go default idle")

	assert.Error(t, SetAligned(c, 0), "a zero period must be refused")
	p1, p2 := net.Pipe()
	defer p1.Close()
	defer p2.Close()
	assert.ErrorIs(t, SetAligned(p1, time.Minute), ErrNotTCP)
}
