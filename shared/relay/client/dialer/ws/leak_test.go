package ws

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// connTracker records the last state of every server-side connection.
type connTracker struct {
	mu     sync.Mutex
	states map[net.Conn]http.ConnState
}

func (c *connTracker) track(conn net.Conn, state http.ConnState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.states[conn] = state
}

func (c *connTracker) open() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, s := range c.states {
		if s != http.StateClosed && s != http.StateHijacked {
			n++
		}
	}
	return n
}

// A proxy in front of a restarting relay answers the upgrade with a short
// keep-alive error, such as Traefik's 11 byte 502. The failed dial must not
// leave that connection open in a transport nobody can reach anymore.
func TestDialClosesConnOnShortKeepAliveError(t *testing.T) {
	tracker := &connTracker{states: map[net.Conn]http.ConnState{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("Bad Gateway"))
	}))
	srv.Config.ConnState = tracker.track
	srv.Start()
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addr := "rel://" + strings.TrimPrefix(srv.URL, "http://")
	conn, err := Dialer{}.Dial(ctx, addr, "")
	require.Error(t, err, "dial must fail on a 502 reply")
	require.Nil(t, conn)

	assert.Eventually(t, func() bool { return tracker.open() == 0 }, time.Second, 10*time.Millisecond,
		"the connection that got the 502 must be closed after the failed dial")
}

// With keep-alives off, the upgrade request must still go out without
// "Connection: close", and the dial must succeed.
func TestDialUpgradeStillWorks(t *testing.T) {
	var gotConnection []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotConnection = r.Header.Values("Connection")
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		_ = c.Close(websocket.StatusNormalClosure, "")
	}))
	t.Cleanup(srv.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := Dialer{}.Dial(ctx, "rel://"+strings.TrimPrefix(srv.URL, "http://"), "")
	require.NoError(t, err)
	_ = conn.Close()

	assert.Equal(t, []string{"Upgrade"}, gotConnection, "upgrade request must carry only Connection: Upgrade")
}
