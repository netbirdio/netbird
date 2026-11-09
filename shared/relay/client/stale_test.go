package client

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/relay/server"
)

// jumpClock is a wall clock moved by hand whose timers run at once, so a
// CheckNow is checked without waiting out the grace.
type jumpClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *jumpClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *jumpClock) AfterFunc(_ time.Duration, f func()) { go f() }

func (c *jumpClock) jump(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// A stale relay connection takes the health check timeout path: the
// connection closes and the disconnect listener runs, which is what starts
// the reconnect in the manager.
func TestStaleRelayTakesHealthCheckTimeoutPath(t *testing.T) {
	clk := &jumpClock{now: time.Now()}
	restore := hbwatch.SetDefault(hbwatch.New(clk, 30*time.Second))
	t.Cleanup(restore)

	ctx := context.Background()
	serverListenAddr := "127.0.0.1:52501"
	serverCfg := newClientTestServerConfig(serverListenAddr)
	srv, err := server.NewServer(serverCfg)
	require.NoError(t, err)
	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(server.ListenerConfig{Address: serverListenAddr}); err != nil {
			errChan <- err
		}
	}()
	t.Cleanup(func() { _ = srv.Shutdown(ctx) })
	require.NoError(t, waitForServerToStart(errChan))

	relayClient := NewClient(serverCfg.ExposedAddress, hmacTokenStore, "alice", iface.DefaultMTU)
	require.NoError(t, relayClient.Connect(ctx))
	t.Cleanup(func() { _ = relayClient.Close() })

	disconnected := make(chan struct{})
	relayClient.SetOnDisconnectListener(func(string) { close(disconnected) })

	// Fresh connection: a wake within the period does nothing.
	clk.jump(10 * time.Second)
	hbwatch.CheckNow()
	select {
	case <-disconnected:
		t.Fatal("a fresh relay connection must not be closed")
	case <-time.After(300 * time.Millisecond):
	}
	assert.True(t, relayClient.Ready(), "relay client must stay connected within the period")

	// The phone slept past period + tolerance with no health check. A Signal
	// test heartbeat marks a test mode, so the stale check acts.
	clk.jump(60 * time.Second)
	hbwatch.Seen(hbwatch.Signal)
	hbwatch.CheckNow()
	select {
	case <-disconnected:
	case <-time.After(3 * time.Second):
		t.Fatal("stale relay connection did not take the timeout path")
	}
	assert.False(t, relayClient.Ready(), "relay client must be closed after the stale action")
}
