package grpc

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setClientPeriod(t *testing.T, period time.Duration, ok bool) {
	t.Helper()
	prev := clientPeriod
	clientPeriod = func() (time.Duration, bool) { return period, ok }
	t.Cleanup(func() { clientPeriod = prev })
}

func TestKeepaliveTime(t *testing.T) {
	const addr = "nb.example:443"
	const mgmt, signal = "/management", "/signal"
	t.Cleanup(func() { ClearStock(mgmt, addr); ClearStock(signal, addr) })

	setClientPeriod(t, 0, false)
	assert.Equal(t, stockKeepaliveTime, KeepaliveTime(mgmt, addr), "client without the aligned heartbeat")

	setClientPeriod(t, time.Minute, true)
	assert.Equal(t, 70*time.Second, KeepaliveTime(mgmt, addr), "aligned client at a 60 s period")

	assert.True(t, MarkStock(mgmt, addr), "first stock answer adds the mark")
	assert.False(t, MarkStock(mgmt, addr), "a second stock answer adds nothing")
	assert.Equal(t, stockKeepaliveTime, KeepaliveTime(mgmt, addr), "a server marked stock gets the stock keepalive")
	assert.Equal(t, 70*time.Second, KeepaliveTime(mgmt, "other.example:443"), "the mark is per address")

	// Self-hosted Management and Signal on one address answer on their own.
	assert.Equal(t, 70*time.Second, KeepaliveTime(signal, addr), "the Management mark does not cover Signal")
	ClearStock(signal, addr)
	assert.Equal(t, stockKeepaliveTime, KeepaliveTime(mgmt, addr), "a Signal answer leaves the Management mark in place")

	ClearStock(mgmt, addr)
	assert.Equal(t, 70*time.Second, KeepaliveTime(mgmt, addr), "an aligned answer clears the mark")
	assert.True(t, MarkStock(mgmt, addr), "a new mark after the clear")
}

func loopbackConn(t *testing.T) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err == nil {
			t.Cleanup(func() { _ = c.Close() })
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestTCPKeepAliveFollowsAnswer(t *testing.T) {
	var k TCPKeepAlive

	// No connection yet: an answer has nothing to apply to.
	k.SetAligned(time.Minute)
	assert.Zero(t, k.period, "no connection tracked")

	k.track(loopbackConn(t))
	k.SetAligned(time.Minute)
	assert.Equal(t, time.Minute, k.period, "aligned answer applied")

	k.SetStock()
	assert.Zero(t, k.period, "stock answer applied")

	k.SetAligned(time.Minute)
	k.track(loopbackConn(t))
	assert.Zero(t, k.period, "a new connection starts stock")

	k.SetAligned(0)
	assert.Zero(t, k.period, "a zero period is ignored")

	p1, p2 := net.Pipe()
	t.Cleanup(func() { _ = p1.Close(); _ = p2.Close() })
	k.track(p1)
	k.SetAligned(time.Minute)
	assert.Zero(t, k.period, "a connection without a TCP socket stays as dialed")
}

func TestTCPKeepAliveNil(t *testing.T) {
	var k *TCPKeepAlive
	assert.NotPanics(t, func() {
		k.track(nil)
		k.SetAligned(time.Minute)
		k.SetStock()
	})
}
