//go:build !js && !ios && !android

package server

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A session's last write is often one stuck on a peer that stopped reading,
// and Close is what unblocks it. The final tick has to be taken after that
// write returns, or the session's closing metrics leave it out.
func TestMetricsConn_FinalTickCountsInFlightWrite(t *testing.T) {
	local, remote := net.Pipe()
	t.Cleanup(func() { _ = remote.Close() })

	var mu sync.Mutex
	var ticks []SessionTick
	conn := newMetricsConn(local, func(tick SessionTick) {
		mu.Lock()
		ticks = append(ticks, tick)
		mu.Unlock()
	})

	// Nothing reads remote, so this Write blocks until the pipe is closed.
	writing := make(chan struct{})
	wrote := make(chan struct{})
	go func() {
		close(writing)
		_, _ = conn.Write([]byte("frame"))
		close(wrote)
	}()
	<-writing
	time.Sleep(20 * time.Millisecond)

	require.NoError(t, conn.Close())
	select {
	case <-wrote:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not unblock the in-flight write")
	}

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, ticks, "Close must emit a final tick")
	final := ticks[len(ticks)-1]
	assert.Equal(t, uint64(1), final.Writes, "the write in flight at Close must be counted in the final tick")
}

// A proxied service-mode connection never sees FBU boundaries, so its ticks
// must say so rather than report zero updates.
func TestMetricsConn_ProxyReportsFBUsUntracked(t *testing.T) {
	local, remote := net.Pipe()
	t.Cleanup(func() { _ = remote.Close() })
	go func() { buf := make([]byte, 64); _, _ = remote.Read(buf) }()

	var got []SessionTick
	var mu sync.Mutex
	conn := newProxyMetricsConn(local, func(tick SessionTick) {
		mu.Lock()
		got = append(got, tick)
		mu.Unlock()
	})
	_, _ = conn.Write([]byte("x"))
	require.NoError(t, conn.Close())

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, got)
	assert.False(t, got[len(got)-1].FBUsTracked, "a proxied connection's FBU fields are unknown, not zero")
}
