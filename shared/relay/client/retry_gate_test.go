package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/relay/server"
)

// retryHeld reports whether w holds a Management retry on a sleeping device
// past the fast window, with no heartbeat wake yet.
func retryHeld(t *testing.T, w *hbwatch.Watcher, clk *jumpClock) bool {
	t.Helper()
	w.SetDeviceAsleep(true)
	down := clk.Now().Add(-hbwatch.FastRetryWindow - time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := w.WaitManagementRetry(ctx, hbwatch.RetrySync, down, nil)
	return errors.Is(err, context.DeadlineExceeded)
}

// A relay connection that the server accepted on v2 with an aligned period
// will bring a heartbeat wake, so it holds Management retries before its first
// heartbeat. A stock v1 connection does not.
func TestRelayOpenedAlignedHoldsManagementRetry(t *testing.T) {
	clk := &jumpClock{now: time.Now()}
	w := hbwatch.New(clk, 30*time.Second)
	t.Cleanup(hbwatch.SetDefault(w))

	ctx := context.Background()
	addr := "127.0.0.1:52502"
	serverCfg := newClientTestServerConfig(addr)
	srv, err := server.NewServer(serverCfg)
	require.NoError(t, err)
	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(server.ListenerConfig{Address: addr}); err != nil {
			errChan <- err
		}
	}()
	t.Cleanup(func() { _ = srv.Shutdown(ctx) })
	require.NoError(t, waitForServerToStart(errChan))

	stock := NewClient(serverCfg.ExposedAddress, hmacTokenStore, "bob", iface.DefaultMTU)
	require.NoError(t, stock.Connect(ctx))
	t.Cleanup(func() { _ = stock.Close() })
	require.Zero(t, stock.alignedPeriod, "precondition: stock connection")
	assert.False(t, retryHeld(t, w, clk), "a stock relay connection must not hold the retry")

	aligned := NewClient(serverCfg.ExposedAddress, tokenStore(t), "alice", iface.DefaultMTU)
	aligned.alignedRequest = askAligned(60 * time.Second)
	require.NoError(t, aligned.Connect(ctx))
	t.Cleanup(func() { _ = aligned.Close() })
	require.Equal(t, 60*time.Second, aligned.alignedPeriod, "precondition: aligned connection")
	assert.True(t, retryHeld(t, w, clk), "an aligned relay connection must hold the retry before its first heartbeat")
}
