package client

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/relay/server"
)

// startManagerTestRelay starts a relay server on address and returns a Manager that
// uses it as its home relay.
func startManagerTestRelay(t *testing.T, ctx context.Context, address, peerID string) *Manager {
	t.Helper()

	cfg := server.ListenerConfig{Address: address}
	srv, err := server.NewServer(newManagerTestServerConfig(cfg.Address))
	require.NoError(t, err)

	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(cfg); err != nil {
			errChan <- err
		}
	}()
	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
	})
	require.NoError(t, waitForServerToStart(errChan))

	m := NewManager(ctx, toURL(cfg), peerID, iface.DefaultMTU)
	require.NoError(t, m.Serve())
	return m
}

// TestOpenConn_DoesNotHoldRelayClientLockAcrossDial asserts that dialing an
// unreachable foreign relay does not stall the relay bookkeeping of the whole node.
// onServerDisconnected needs relayClientMu in write mode, and a pending writer also
// blocks later readers, so holding the lock across the dial made one unreachable
// relay freeze every relay operation for as long as that server's connect timeout.
func TestOpenConn_DoesNotHoldRelayClientLockAcrossDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	m := startManagerTestRelay(t, ctx, "localhost:52801", "alice")
	stalling := stallingRelayListener(t)

	dialDone := make(chan struct{})
	go func() {
		defer close(dialDone)
		_, _ = m.OpenConn(ctx, stalling, "bob", netip.Addr{})
	}()

	// The track is published before the dial starts, so its presence means the dial
	// is in flight and the lock, if taken, is held.
	require.Eventually(t, func() bool {
		m.relayClientsMutex.RLock()
		defer m.relayClientsMutex.RUnlock()
		_, ok := m.relayClients[stalling]
		return ok
	}, 5*time.Second, 5*time.Millisecond, "the foreign relay dial did not start")

	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		m.onServerDisconnected("rel://192.0.2.1:1234")
	}()

	select {
	case <-writerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("onServerDisconnected blocked on an in-progress foreign relay dial")
	}

	cancel()
	select {
	case <-dialDone:
	case <-time.After(5 * time.Second):
		t.Fatal("OpenConn did not return after context cancellation")
	}
}

// TestEvictForeignRelay_KeepsConnectedClient asserts that a disconnect notice naming a
// server whose track has since been rebuilt does not drop the live client. Evicting it
// makes the next OpenConn build a duplicate connection, which the relay answers by
// closing the existing one and with it every relayed channel on that server.
func TestEvictForeignRelay_KeepsConnectedClient(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	alice := startManagerTestRelay(t, ctx, "localhost:52802", "alice")
	bob := startManagerTestRelay(t, ctx, "localhost:52803", "bob")

	bobsSrvAddr, _, err := bob.RelayInstanceAddress()
	require.NoError(t, err)

	_, err = alice.OpenConn(ctx, bobsSrvAddr, "bob", netip.Addr{})
	require.NoError(t, err, "alice must reach bob over bob's relay")

	alice.relayClientsMutex.RLock()
	rt, tracked := alice.relayClients[bobsSrvAddr]
	alice.relayClientsMutex.RUnlock()
	require.True(t, tracked, "the foreign relay must be tracked after OpenConn")
	rt.RLock()
	require.True(t, rt.relayClient.Ready(), "the foreign relay client must be connected")
	rt.RUnlock()

	// A disconnect notice for the same address, delivered late.
	alice.evictForeignRelay(bobsSrvAddr)

	alice.relayClientsMutex.RLock()
	_, stillTracked := alice.relayClients[bobsSrvAddr]
	alice.relayClientsMutex.RUnlock()
	require.True(t, stillTracked, "a late disconnect notice must not evict a connected foreign relay client")
}

// TestEvictForeignRelay_KeepsDialInProgress asserts that a disconnect notice arriving
// while a new dial for the same server is still running does not delete the track.
// openConnVia publishes the track before dialing and only fills relayClient once the
// dial finishes, so an eviction in that window orphans the client that is about to
// connect: it is no longer reachable through the map, cleanUpUnusedRelays cannot close
// it, and the next OpenConn dials a duplicate the relay answers by closing the first.
func TestEvictForeignRelay_KeepsDialInProgress(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	m := NewManager(ctx, nil, "alice", iface.DefaultMTU)
	stalling := stallingRelayListener(t)

	dialDone := make(chan struct{})
	go func() {
		defer close(dialDone)
		_, _ = m.openConnVia(ctx, stalling, "bob", netip.Addr{})
	}()

	require.Eventually(t, func() bool {
		m.relayClientsMutex.RLock()
		defer m.relayClientsMutex.RUnlock()
		_, ok := m.relayClients[stalling]
		return ok
	}, 5*time.Second, 5*time.Millisecond, "the foreign relay dial did not start")

	m.evictForeignRelay(stalling)

	m.relayClientsMutex.RLock()
	_, stillTracked := m.relayClients[stalling]
	m.relayClientsMutex.RUnlock()
	require.True(t, stillTracked, "a disconnect notice must not evict a track whose dial is still in progress")

	cancel()
	select {
	case <-dialDone:
	case <-time.After(5 * time.Second):
		t.Fatal("openConnVia did not return after context cancellation")
	}
}
