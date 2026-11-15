//go:build linux || darwin

package ws

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/shared/alignedhb"
)

// goDefaultKeepAliveIdle is the idle time Go sets on accepted TCP connections
// when the listener leaves keepalive at its default.
const goDefaultKeepAliveIdle = 15 * time.Second

func sockoptInt(t *testing.T, c net.Conn, level, opt int) int {
	t.Helper()
	raw, err := c.(*net.TCPConn).SyscallConn()
	require.NoError(t, err)
	var v int
	var sockErr error
	require.NoError(t, raw.Control(func(fd uintptr) {
		v, sockErr = unix.GetsockoptInt(int(fd), level, opt)
	}))
	require.NoError(t, sockErr)
	return v
}

// The relay calls UseAlignedHeartbeat only on aligned connections
// (TestRelay_OnlyAlignedTunesTransport), so an accepted connection without the
// call is what a stock client gets. Aligned connections get the idle rule of
// Management and Signal.
func TestConn_KeepAliveIdleOnlyAfterTuning(t *testing.T) {
	l := &Listener{Address: "127.0.0.1:0"}
	require.NoError(t, l.Bind())
	c := acceptOne(t, l)

	assert.NotZero(t, sockoptInt(t, c.netConn, unix.SOL_SOCKET, unix.SO_KEEPALIVE), "stock connection keepalive on")
	assert.Equal(t, int(goDefaultKeepAliveIdle.Seconds()), sockoptInt(t, c.netConn, unix.IPPROTO_TCP, keepAliveIdleOpt),
		"stock connection keeps the Go default idle time")

	require.NoError(t, c.UseAlignedHeartbeat(time.Minute))
	assert.NotZero(t, sockoptInt(t, c.netConn, unix.SOL_SOCKET, unix.SO_KEEPALIVE), "aligned connection keepalive on")
	assert.Equal(t, int(alignedhb.TCPKeepAliveIdle(time.Minute).Seconds()), sockoptInt(t, c.netConn, unix.IPPROTO_TCP, keepAliveIdleOpt),
		"aligned connection idle time")
}
