package ws

import (
	"context"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	relaylistener "github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/shared/testhb"
)

// testhb reads its env once per process, so the test runs itself in a child
// process with dynamic mode set.
func TestListenerCarriesTestHBSchedule(t *testing.T) {
	if os.Getenv("NB_TEST_HB_MODE") == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestListenerCarriesTestHBSchedule$", "-test.v")
		cmd.Env = append(os.Environ(), "NB_TEST_HB_MODE=dynamic")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return
	}

	l := &Listener{Address: "127.0.0.1:0"}
	require.NoError(t, l.Bind())
	conns := make(chan relaylistener.Conn, 2)
	go func() { _ = l.Serve(func(c relaylistener.Conn) { conns <- c }) }()
	t.Cleanup(func() { _ = l.Shutdown(context.Background()) })
	base := "ws://" + l.listener.Addr().String() + URLPath

	accept := func(rawURL string) testhb.ClientSchedule {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, _, err := websocket.Dial(ctx, rawURL, nil) //nolint:bodyclose
		require.NoError(t, err)
		defer func() { _ = c.CloseNow() }()
		select {
		case conn := <-conns:
			defer func() { _ = conn.Close() }()
			wsConn, ok := conn.(*Conn)
			require.True(t, ok, "listener must hand over a ws Conn")
			return wsConn.TestHBSchedule()
		case <-time.After(3 * time.Second):
			t.Fatal("connection not accepted")
			return testhb.ClientSchedule{}
		}
	}

	sent := time.Now().UnixMilli()
	value := "p=17342;period=30;t=" + strconv.FormatInt(sent, 10)
	cs := accept(base + "?" + testhb.RelayQueryParam + "=" + url.QueryEscape(value))
	assert.True(t, cs.OK, "schedule must reach the conn")
	assert.Equal(t, int64(17342), cs.PhaseMs, "phase")
	assert.Equal(t, 30*time.Second, cs.Period, "period")
	assert.True(t, cs.SkewMs >= 0 && cs.SkewMs < 1000, "skew %d ms on loopback", cs.SkewMs)

	assert.False(t, accept(base).OK, "no nbhb must give no schedule")
}
