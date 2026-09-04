//go:build linux

package net

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// relaySocketBufferFloor is a lower bound on the readback SO_RCVBUF/SO_SNDBUF
// after sizing. The kernel doubles the requested value on readback; unprivileged
// runs are clamped to net.core.rmem_max (commonly 212992, doubling to 425984),
// while privileged runs reach close to the configured default of 7 MiB. This
// floor holds in both cases while still proving growth over the ~208 KiB OS
// default.
const relaySocketBufferFloor = 416 * 1024

func getSockBuffers(t *testing.T, conn *net.UDPConn) (rcv, snd int) {
	t.Helper()

	sc, err := conn.SyscallConn()
	require.NoError(t, err)

	var ctrlErr error
	err = sc.Control(func(fd uintptr) {
		rcv, ctrlErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF)
		if ctrlErr != nil {
			return
		}
		snd, ctrlErr = unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF)
	})
	require.NoError(t, err)
	require.NoError(t, ctrlErr)
	return rcv, snd
}

func TestSizeRelaySocketBuffersGrowsBuffers(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer conn.Close()

	rcvBefore, sndBefore := getSockBuffers(t, conn)

	SizeRelaySocketBuffers(conn)

	rcvAfter, sndAfter := getSockBuffers(t, conn)

	assert.GreaterOrEqual(t, rcvAfter, relaySocketBufferFloor)
	assert.GreaterOrEqual(t, sndAfter, relaySocketBufferFloor)
	assert.GreaterOrEqual(t, rcvAfter, rcvBefore)
	assert.GreaterOrEqual(t, sndAfter, sndBefore)
}

func TestSizeRelaySocketBuffersEnvDisable(t *testing.T) {
	t.Setenv(relaySocketBufferEnv, "0")

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer conn.Close()

	rcvBefore, sndBefore := getSockBuffers(t, conn)

	SizeRelaySocketBuffers(conn)

	rcvAfter, sndAfter := getSockBuffers(t, conn)

	assert.Equal(t, rcvBefore, rcvAfter)
	assert.Equal(t, sndBefore, sndAfter)
}
