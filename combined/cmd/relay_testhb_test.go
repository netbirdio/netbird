package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/relay/server/listener/ws"
	"github.com/netbirdio/netbird/shared/testhb"
)

// The combined server accepts relay WebSockets in its own handler, not in
// ws.Listener, so it must carry the client schedule too. testhb reads its env
// once per process, so the test runs itself in a child with dynamic mode set.
func TestCombinedRelayHandlerCarriesTestHBSchedule(t *testing.T) {
	if os.Getenv("NB_TEST_HB_MODE") == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestCombinedRelayHandlerCarriesTestHBSchedule$", "-test.v")
		cmd.Env = append(os.Environ(), "NB_TEST_HB_MODE=dynamic")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, string(out))
		return
	}

	conns := make(chan listener.Conn, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleRelayWebSocket(w, r, func(c listener.Conn) { conns <- c }, &CombinedConfig{})
	}))
	t.Cleanup(srv.Close)
	base := "ws" + strings.TrimPrefix(srv.URL, "http") + "/relay"

	accept := func(rawURL string) testhb.ClientSchedule {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		c, _, err := websocket.Dial(ctx, rawURL, nil) //nolint:bodyclose
		require.NoError(t, err)
		defer func() { _ = c.CloseNow() }()
		select {
		case conn := <-conns:
			defer func() { _ = conn.Close() }()
			wsConn, ok := conn.(*ws.Conn)
			require.True(t, ok, "handler must hand over a ws Conn")
			return wsConn.TestHBSchedule()
		case <-time.After(3 * time.Second):
			t.Fatal("connection not accepted")
			return testhb.ClientSchedule{}
		}
	}

	value := "p=17342;period=30;t=" + strconv.FormatInt(time.Now().UnixMilli(), 10)
	cs := accept(base + "?" + testhb.RelayQueryParam + "=" + url.QueryEscape(value))
	assert.True(t, cs.OK, "schedule must reach the conn")
	assert.Equal(t, int64(17342), cs.PhaseMs, "phase")
	assert.Equal(t, 30*time.Second, cs.Period, "period")

	assert.False(t, accept(base).OK, "no nbhb must give no schedule")
}
