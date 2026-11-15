package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/relay/server/listener/ws"
	alignedka "github.com/netbirdio/netbird/shared/alignedhb/keepalive"
)

// The combined server accepts relay WebSockets through the Management HTTP
// server. The relay connection must get the accepted socket, so v2 can tune
// its keepalive like the standalone relay listener does.
func TestRelayWebSocketGetsAcceptedConn(t *testing.T) {
	accepted := make(chan listener.Conn, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleRelayWebSocket(w, r, func(c listener.Conn) { accepted <- c }, nil)
	}))
	srv.Config.ConnContext = alignedka.ConnContext
	srv.Start()
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	require.NoError(t, err)
	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	defer func() { _ = c.CloseNow() }()

	var conn listener.Conn
	select {
	case conn = <-accepted:
	case <-ctx.Done():
		t.Fatal("relay connection not accepted")
	}
	wsConn, ok := conn.(*ws.Conn)
	require.True(t, ok, "relay ws connection, got %T", conn)
	assert.NoError(t, wsConn.UseAlignedHeartbeat(time.Minute), "the accepted socket must be reachable for aligned tuning")
}
