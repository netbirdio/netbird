//go:build linux || darwin

package server

import (
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func acceptedKeepalive(t *testing.T, ka testKeepalive) bool {
	t.Helper()

	ln, err := ka.listen("127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	client, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	conn, err := ln.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	raw, err := conn.(*net.TCPConn).SyscallConn()
	require.NoError(t, err)

	var val int
	var sockErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		val, sockErr = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE)
	}))
	require.NoError(t, sockErr)
	return val != 0
}

func TestTestKeepaliveListenStock(t *testing.T) {
	assert.True(t, acceptedKeepalive(t, testKeepalive{}), "stock net.Listen enables TCP keepalive on accept")
}

func TestTestKeepaliveListenOff(t *testing.T) {
	assert.False(t, acceptedKeepalive(t, testKeepalive{tcpSet: true, tcp: -1}), "-1 must disable TCP keepalive")
}

func TestTestKeepaliveListenOn(t *testing.T) {
	assert.True(t, acceptedKeepalive(t, testKeepalive{tcpSet: true, tcp: 120 * time.Second}), "positive value must enable TCP keepalive")
}
