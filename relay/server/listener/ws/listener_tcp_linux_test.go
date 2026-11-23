package ws

import (
	"context"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestListener_AcceptedSocketOptions(t *testing.T) {
	l := &Listener{Address: "127.0.0.1:0"}
	require.NoError(t, l.Bind())
	t.Cleanup(func() { _ = l.Shutdown(context.Background()) })

	client, err := net.Dial("tcp", l.listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	conn, err := l.listener.Accept()
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	tcpConn, ok := conn.(*net.TCPConn)
	require.True(t, ok, "accepted connection must be TCP")
	raw, err := tcpConn.SyscallConn()
	require.NoError(t, err)

	keepAlive := sockoptInt(t, raw, unix.SOL_SOCKET, unix.SO_KEEPALIVE)
	idle := sockoptInt(t, raw, unix.IPPROTO_TCP, unix.TCP_KEEPIDLE)
	userTimeout := sockoptInt(t, raw, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT)

	assert.Equal(t, 1, keepAlive, "SO_KEEPALIVE")
	assert.Equal(t, 600, idle, "TCP_KEEPIDLE seconds")
	assert.Equal(t, 20000, userTimeout, "TCP_USER_TIMEOUT milliseconds")
}

func sockoptInt(t *testing.T, raw syscall.RawConn, level, opt int) int {
	t.Helper()
	var (
		val     int
		sockErr error
	)
	require.NoError(t, raw.Control(func(fd uintptr) {
		val, sockErr = unix.GetsockoptInt(int(fd), level, opt)
	}))
	require.NoError(t, sockErr)
	return val
}
