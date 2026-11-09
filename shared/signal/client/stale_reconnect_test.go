package client

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/hbwatch"
	sigProto "github.com/netbirdio/netbird/shared/signal/proto"
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

// A stale Signal stream is reconnected at once, without a probe first. The
// server here is alive and would answer a probe, so only a direct reconnect
// opens a second stream.
func TestStaleSignalReconnectsWithoutProbe(t *testing.T) {
	clk := &jumpClock{now: time.Now()}
	restore := hbwatch.SetDefault(hbwatch.New(clk, 30*time.Second))
	t.Cleanup(restore)

	addr := startTestSignalServer(t)
	key, err := wgtypes.GenerateKey()
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c, err := NewClient(ctx, addr, key, false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })

	var streams atomic.Int32
	c.SetOnReconnectedListener(func() { streams.Add(1) })
	go func() {
		_ = c.Receive(ctx, func(*sigProto.Message) error { return nil })
	}()
	require.Eventually(t, func() bool { return streams.Load() == 1 }, 5*time.Second, 10*time.Millisecond,
		"first stream must open")

	// Jump past period + tolerance and wake. A Management test heartbeat keeps
	// the gate open without touching the Signal stream.
	require.Eventually(t, func() bool {
		clk.jump(60 * time.Second)
		hbwatch.Seen(hbwatch.Management)
		hbwatch.CheckNow()
		return streams.Load() >= 2
	}, 3*time.Second, 50*time.Millisecond, "a stale Signal stream must reconnect without waiting for a probe")
	require.NoError(t, ctx.Err(), "the parent context is untouched")
}
