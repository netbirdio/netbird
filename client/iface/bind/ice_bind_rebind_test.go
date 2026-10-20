package bind

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The engine reads the ICE mux once, when the interface comes up, and hands it
// to every peer. A rebind (BindUpdate: Close then Open on a new socket) must
// not leave that mux behind on the closed socket, or every ICE agent created
// afterwards sends from a dead socket and P2P never comes back.
func TestICEBind_MuxSurvivesRebind(t *testing.T) {
	iceBind := setupICEBind(t)

	_, port, err := iceBind.Open(0)
	require.NoError(t, err)
	before, err := iceBind.GetICEMux()
	require.NoError(t, err)

	require.NoError(t, iceBind.Close())
	_, _, err = iceBind.Open(port)
	require.NoError(t, err)
	t.Cleanup(func() { _ = iceBind.Close() })

	after, err := iceBind.GetICEMux()
	require.NoError(t, err)
	assert.Same(t, before, after, "the mux handed out before the rebind must stay the one in use")

	listener := listenUDP(t, "udp4", "127.0.0.1:0")
	_, err = before.GetSharedConn().WriteTo([]byte("probe"), listener.LocalAddr())
	require.NoError(t, err, "the mux taken before the rebind must write on the new socket")

	require.NoError(t, listener.SetReadDeadline(time.Now().Add(2*time.Second)))
	buf := make([]byte, 16)
	n, from, err := listener.ReadFrom(buf)
	require.NoError(t, err, "the probe sent through the old mux must arrive")
	assert.Equal(t, "probe", string(buf[:n]), "probe payload")
	assert.Equal(t, int(port), from.(*net.UDPAddr).Port, "the probe must leave from the rebound WireGuard port")
}
