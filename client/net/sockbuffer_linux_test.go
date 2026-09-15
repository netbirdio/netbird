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

// setSockBuffers applies size with the unforced SO_RCVBUF/SO_SNDBUF, which works without
// privilege while size stays under rmem_max/wmem_max, and returns the kernel readback.
func setSockBuffers(t *testing.T, conn *net.UDPConn, size int) (rcv, snd int) {
	t.Helper()

	sc, err := conn.SyscallConn()
	require.NoError(t, err)

	var ctrlErr error
	err = sc.Control(func(fd uintptr) {
		ctrlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, size)
		if ctrlErr != nil {
			return
		}
		ctrlErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, size)
	})
	require.NoError(t, err)
	require.NoError(t, ctrlErr)

	rcv, snd = getSockBuffers(t, conn)
	require.Equal(t, 2*size, rcv, "precondition: receive buffer readback is doubled")
	require.Equal(t, 2*size, snd, "precondition: send buffer readback is doubled")
	return rcv, snd
}

func listenLoopbackUDP(t *testing.T) *net.UDPConn {
	t.Helper()

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestSizeRelaySocketBuffersGrowsBuffers(t *testing.T) {
	unsetRelaySocketBufferEnv(t)

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

func TestSizeRelaySocketBuffersNeverShrinks(t *testing.T) {
	// A 65536 request reads back as 131072. Asking for 32768 afterwards would read back
	// as 65536, so applying it would halve buffers that are already larger.
	t.Setenv(relaySocketBufferEnv, "32768")

	conn := listenLoopbackUDP(t)
	rcvBefore, sndBefore := setSockBuffers(t, conn, 65536)

	SizeRelaySocketBuffers(conn)

	rcvAfter, sndAfter := getSockBuffers(t, conn)
	assert.Equal(t, rcvBefore, rcvAfter, "receive buffer must not shrink")
	assert.Equal(t, sndBefore, sndAfter, "send buffer must not shrink")
}

func TestSizeRelaySocketBuffersOversizedValue(t *testing.T) {
	// Unclamped, 1<<32 would truncate to 0 in setsockopt's int32 argument and the kernel
	// would apply its minimum buffer. The clamped value must not shrink the buffers either;
	// unprivileged, rmem_max caps the result, so only growth is asserted here.
	t.Setenv(relaySocketBufferEnv, "4294967296")

	conn := listenLoopbackUDP(t)
	rcvBefore, sndBefore := setSockBuffers(t, conn, 65536)

	SizeRelaySocketBuffers(conn)

	rcvAfter, sndAfter := getSockBuffers(t, conn)
	assert.GreaterOrEqual(t, rcvAfter, rcvBefore, "receive buffer must not shrink")
	assert.GreaterOrEqual(t, sndAfter, sndBefore, "send buffer must not shrink")
}

func TestSizeRelaySocketBuffersComparesKernelUnits(t *testing.T) {
	// The buffers read back 131072. A 98304 request is below that as a raw number but reads
	// back as 196608 once applied, so it still grows them. Comparing the readback against
	// the unscaled request would wrongly skip it.
	t.Setenv(relaySocketBufferEnv, "98304")

	conn := listenLoopbackUDP(t)
	setSockBuffers(t, conn, 65536)

	SizeRelaySocketBuffers(conn)

	rcvAfter, sndAfter := getSockBuffers(t, conn)
	assert.Equal(t, 2*98304, rcvAfter, "receive buffer should reach the requested size")
	assert.Equal(t, 2*98304, sndAfter, "send buffer should reach the requested size")
}
