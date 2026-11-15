package ws

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// keepAliveIdleOpt is the TCP option for the keepalive idle time.
const keepAliveIdleOpt = unix.TCP_KEEPIDLE

// An aligned client may have no radio for longer than a short user timeout
// while the relay has data queued, so tuning must keep the kernel default.
func TestConn_TuningKeepsDefaultUserTimeout(t *testing.T) {
	l := &Listener{Address: "127.0.0.1:0"}
	require.NoError(t, l.Bind())
	c := acceptOne(t, l)

	assert.Zero(t, sockoptInt(t, c.netConn, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT), "stock connection user timeout")
	require.NoError(t, c.UseAlignedHeartbeat(time.Minute))
	assert.Zero(t, sockoptInt(t, c.netConn, unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT), "aligned connection user timeout")
}
