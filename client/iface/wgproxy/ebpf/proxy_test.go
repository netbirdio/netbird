//go:build linux && !android

package ebpf

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWGEBPFProxy_connStore(t *testing.T) {
	wgProxy := NewWGEBPFProxy(51820, 1280)

	p, _ := wgProxy.storeRelayedConn(nil)
	if p != 1 {
		t.Errorf("invalid initial port: %d", wgProxy.lastUsedPort)
	}

	numOfConns := 10
	for i := 0; i < numOfConns; i++ {
		p, _ = wgProxy.storeRelayedConn(nil)
	}
	if p != uint16(numOfConns)+1 {
		t.Errorf("invalid last used port: %d, expected: %d", p, numOfConns+1)
	}
	if len(wgProxy.relayedConnStore) != numOfConns+1 {
		t.Errorf("invalid store size: %d, expected: %d", len(wgProxy.relayedConnStore), numOfConns+1)
	}
}

func TestWGEBPFProxy_portCalculation_overflow(t *testing.T) {
	wgProxy := NewWGEBPFProxy(51820, 1280)

	_, _ = wgProxy.storeRelayedConn(nil)
	wgProxy.lastUsedPort = 65535
	p, _ := wgProxy.storeRelayedConn(nil)

	if len(wgProxy.relayedConnStore) != 2 {
		t.Errorf("invalid store size: %d, expected: %d", len(wgProxy.relayedConnStore), 2)
	}

	if p != 2 {
		t.Errorf("invalid last used port: %d, expected: %d", p, 2)
	}
}

func TestWGEBPFProxy_portCalculation_maxConn(t *testing.T) {
	wgProxy := NewWGEBPFProxy(51820, 1280)

	for i := 0; i < 65535; i++ {
		_, _ = wgProxy.storeRelayedConn(nil)
	}

	_, err := wgProxy.storeRelayedConn(nil)
	if err == nil {
		t.Errorf("invalid relayed conn store calculation")
	}
}

// TestWGEBPFProxy_nextFreePort_SkipsWGListenPort covers the allocator reaching
// the WireGuard listen port. Packets injected from 127.0.0.1:<wg port> match the
// XDP redirect and loop back into the proxy instead of reaching WireGuard.
func TestWGEBPFProxy_nextFreePort_SkipsWGListenPort(t *testing.T) {
	const wgPort = 51820
	wgProxy := NewWGEBPFProxy(wgPort, 1280)
	wgProxy.lastUsedPort = wgPort - 1

	p, err := wgProxy.storeRelayedConn(nil)
	require.NoError(t, err)
	assert.NotEqual(t, uint16(wgPort), p, "the WireGuard listen port must never be handed out")
	assert.Equal(t, uint16(wgPort+1), p, "the allocator must continue after the reserved port")
}

// TestWGEBPFProxy_nextFreePort_ExhaustedBesidesReserved fills every port the
// allocator may hand out. It must report exhaustion instead of returning the
// reserved port or searching forever.
func TestWGEBPFProxy_nextFreePort_ExhaustedBesidesReserved(t *testing.T) {
	const wgPort = 51820
	wgProxy := NewWGEBPFProxy(wgPort, 1280)
	for port := 1; port <= math.MaxUint16; port++ {
		if port != wgPort {
			wgProxy.relayedConnStore[uint16(port)] = nil
		}
	}

	type result struct {
		port uint16
		err  error
	}
	done := make(chan result, 1)
	go func() {
		p, err := wgProxy.storeRelayedConn(nil)
		done <- result{p, err}
	}()

	select {
	case r := <-done:
		assert.Error(t, r.err, "a table without a usable port must be reported as full, got port %d", r.port)
	case <-time.After(10 * time.Second):
		t.Fatal("port allocation did not return on an exhausted table")
	}
}
