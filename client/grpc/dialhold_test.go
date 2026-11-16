//go:build !js

package grpc

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/netbirdio/netbird/client/hbwatch"
)

// offsetClock is the wall clock plus an offset the test moves forward.
type offsetClock struct {
	mu  sync.Mutex
	off time.Duration
}

func (c *offsetClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Now().Add(c.off)
}

func (c *offsetClock) AfterFunc(d time.Duration, f func()) { time.AfterFunc(d, f) }

func (c *offsetClock) jump(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.off += d
}

func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// While Management refuses connections the gRPC channel redials on its own
// backoff. On a locked, idle phone those dials wait in the dial hook for a
// wake, and the wake lets exactly one through.
func TestDialHoldOnClosedPort(t *testing.T) {
	clk := &offsetClock{}
	w := hbwatch.New(clk, 30*time.Second)
	// An aligned Signal stream ticks, so a heartbeat wake will come.
	w.Register(hbwatch.Signal, hbwatch.Registration{Kind: hbwatch.ActionReconnect, Stale: func() {}})
	w.Seen(hbwatch.Signal, hbwatch.Heartbeat{Period: 30 * time.Second})
	w.SetDeviceAsleep(true)
	down := clk.Now()
	clk.jump(2 * time.Minute)

	var entered, dialed atomic.Int32
	hold := func(ctx context.Context) error {
		entered.Add(1)
		if _, err := w.WaitManagementRetry(ctx, hbwatch.RetryDial, down, nil); err != nil {
			return err
		}
		dialed.Add(1)
		return nil
	}

	conn, err := grpc.NewClient(closedPort(t),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		WithDialHooks(nil, nil, hold))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	conn.Connect()

	require.Eventually(t, func() bool { return entered.Load() > 0 }, 5*time.Second, 10*time.Millisecond,
		"the channel must try to dial by itself")
	time.Sleep(3 * time.Second)
	assert.Zero(t, dialed.Load(), "no dial while the gate holds")

	w.Seen(hbwatch.Signal, hbwatch.Heartbeat{Period: 30 * time.Second})
	conn.ResetConnectBackoff()
	require.Eventually(t, func() bool { return dialed.Load() == 1 }, 5*time.Second, 10*time.Millisecond,
		"the wake lets one dial through")
	time.Sleep(3 * time.Second)
	assert.Equal(t, int32(1), dialed.Load(), "one dial per wake, the next ones wait for the next period")
	assert.Greater(t, entered.Load(), int32(1), "the channel kept redialing on its own")
}
