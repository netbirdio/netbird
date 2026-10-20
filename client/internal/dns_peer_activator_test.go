package internal

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/internal/peer"
	"github.com/netbirdio/netbird/client/internal/peerstore"
)

func newTestPeerConn(t *testing.T, key string) *peer.Conn {
	t.Helper()
	conn, err := peer.NewConn(peer.ConnConfig{
		Key:      key,
		LocalKey: "local",
		WgConfig: peer.WgConfig{
			AllowedIps: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
		},
	}, peer.ServiceDependencies{})
	require.NoError(t, err)
	return conn
}

func newTestDNSPeerActivator(t *testing.T) (*dnsPeerActivator, *peer.Status, *peerstore.Store) {
	t.Helper()
	status := peer.NewRecorder("https://mgm")
	store := peerstore.NewConnStore()
	// ConnMgr without Start: the lazy manager is nil, so ActivatePeer is a
	// no-op — these tests exercise the activator's skip/wait logic.
	connMgr := NewConnMgr(&EngineConfig{}, status, store, nil)
	return &dnsPeerActivator{
		connMgr:   connMgr,
		peerStore: store,
		status:    status,
		ctx:       context.Background(),
	}, status, store
}

func TestDNSPeerActivator_NilSafe(t *testing.T) {
	var a *dnsPeerActivator
	a.ActivatePeersByIP(context.Background(), []netip.Addr{netip.MustParseAddr("100.64.0.1")})
}

// TestDNSPeerActivator_SkipsUnknownAndConnectedPeers verifies the steady-state
// (warm) path adds no latency: already-connected and unknown addresses never
// enter the wait loop.
func TestDNSPeerActivator_SkipsUnknownAndConnectedPeers(t *testing.T) {
	a, status, store := newTestDNSPeerActivator(t)

	require.NoError(t, status.AddPeer("peerA", "a.netbird.cloud", "100.64.0.1", "fd00::1"))
	require.NoError(t, status.UpdatePeerState(peer.State{PubKey: "peerA", ConnStatus: peer.StatusConnected}))
	store.AddPeerConn("peerA", newTestPeerConn(t, "peerA"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	a.ActivatePeersByIP(ctx, []netip.Addr{
		netip.MustParseAddr("100.64.0.1"),  // known, connected -> skipped
		netip.MustParseAddr("fd00::1"),     // known via IPv6, connected -> skipped
		netip.MustParseAddr("100.64.0.99"), // unknown -> skipped
	})
	require.Less(t, time.Since(start), time.Second, "no pending peer must mean no wait")
}

// TestDNSPeerActivator_WaitsForPendingPeerToConnect verifies the wait loop
// returns as soon as a pending peer reports connected, well before the
// per-query budget expires.
func TestDNSPeerActivator_WaitsForPendingPeerToConnect(t *testing.T) {
	a, status, store := newTestDNSPeerActivator(t)

	require.NoError(t, status.AddPeer("peerA", "a.netbird.cloud", "100.64.0.1", ""))
	store.AddPeerConn("peerA", newTestPeerConn(t, "peerA"))

	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = status.UpdatePeerState(peer.State{PubKey: "peerA", ConnStatus: peer.StatusConnected})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	a.ActivatePeersByIP(ctx, []netip.Addr{netip.MustParseAddr("100.64.0.1")})
	elapsed := time.Since(start)

	require.GreaterOrEqual(t, elapsed, 100*time.Millisecond, "must wait for the pending peer")
	require.Less(t, elapsed, 5*time.Second, "must return on connect, not at the deadline")
}

// TestDNSPeerActivator_ReturnsAtBudgetWhenPeerStaysIdle verifies a peer that
// never connects releases the DNS response at the per-query budget instead of
// blocking it indefinitely.
func TestDNSPeerActivator_ReturnsAtBudgetWhenPeerStaysIdle(t *testing.T) {
	a, status, store := newTestDNSPeerActivator(t)

	require.NoError(t, status.AddPeer("peerA", "a.netbird.cloud", "100.64.0.1", ""))
	store.AddPeerConn("peerA", newTestPeerConn(t, "peerA"))

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	start := time.Now()
	a.ActivatePeersByIP(ctx, []netip.Addr{netip.MustParseAddr("100.64.0.1")})
	elapsed := time.Since(start)

	require.GreaterOrEqual(t, elapsed, 250*time.Millisecond, "must wait out the budget for a pending peer")
	require.Less(t, elapsed, 5*time.Second, "must not block past the budget")
}

// TestDNSPeerActivator_NoWaitWithoutPeerConn verifies a known-but-idle peer
// with no connection object in the store is not waited on: there is nothing to
// activate, so waiting could only ever time out.
func TestDNSPeerActivator_NoWaitWithoutPeerConn(t *testing.T) {
	a, status, _ := newTestDNSPeerActivator(t)

	require.NoError(t, status.AddPeer("peerA", "a.netbird.cloud", "100.64.0.1", ""))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	a.ActivatePeersByIP(ctx, []netip.Addr{netip.MustParseAddr("100.64.0.1")})
	require.Less(t, time.Since(start), time.Second, "peer without a conn must not be waited on")
}
