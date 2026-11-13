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
// The home supervisor needs relayClientMu in write mode to publish a session, and a
// pending writer also blocks later readers, so holding the lock across the dial made
// one unreachable relay freeze every relay operation for as long as that server's
// connect timeout.
func TestOpenConn_DoesNotHoldRelayClientLockAcrossDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	m := startManagerTestRelay(t, ctx, "localhost:52801", "alice")
	home := homeSession(t, m)
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
		m.adoptHome(home)
	}()

	select {
	case <-writerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("publishing the home session blocked on an in-progress foreign relay dial")
	}

	cancel()
	select {
	case <-dialDone:
	case <-time.After(5 * time.Second):
		t.Fatal("OpenConn did not return after context cancellation")
	}
}

// TestForeignTrack_SurvivesLateEndOfReplacedSession asserts that the end of a session
// whose track has since been rebuilt on the same address does not drop the live track.
// Removing it makes the next OpenConn build a duplicate connection, which the relay
// answers by closing the existing one and with it every relayed channel on that server.
func TestForeignTrack_SurvivesLateEndOfReplacedSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	alice := startManagerTestRelay(t, ctx, "localhost:52802", "alice")
	bob := startManagerTestRelay(t, ctx, "localhost:52803", "bob")

	bobsSrvAddr, _, err := bob.RelayInstanceAddress()
	require.NoError(t, err)

	_, err = alice.OpenConn(ctx, bobsSrvAddr, "bob", netip.Addr{})
	require.NoError(t, err, "alice must reach bob over bob's relay")

	oldTrack := foreignTrack(t, alice, bobsSrvAddr)
	oldSession := trackSession(t, oldTrack)

	// The idle cleanup drops a track from the map before its session has ended,
	// which is how a new track can appear on the same address while the old
	// session is still on its way out.
	alice.relayClientsMutex.Lock()
	delete(alice.relayClients, bobsSrvAddr)
	alice.relayClientsMutex.Unlock()

	_, err = alice.OpenConn(ctx, bobsSrvAddr, "bob", netip.Addr{})
	require.NoError(t, err, "alice must reach bob again over a rebuilt track")
	newTrack := foreignTrack(t, alice, bobsSrvAddr)
	require.NotSame(t, oldTrack, newTrack, "the second OpenConn must build a new track")

	dropSession(t, oldSession)
	alice.watchForeignSession(bobsSrvAddr, oldTrack, oldSession)

	require.Same(t, newTrack, foreignTrack(t, alice, bobsSrvAddr), "the late end of a replaced session must not remove the new track")
	newTrack.RLock()
	ready := newTrack.relayClient.Ready()
	newTrack.RUnlock()
	require.True(t, ready, "the rebuilt foreign relay client must stay connected")
}

// TestForeignTrack_DialInProgressSurvivesEndOfOldSession asserts that the end of an
// older session on the same address does not delete a track whose dial is still
// running. openConnVia publishes the track before dialing and only fills relayClient
// once the dial finishes, so a removal in that window orphans the client that is about
// to connect: it is no longer reachable through the map, cleanUpUnusedRelays cannot
// close it, and the next OpenConn dials a duplicate the relay answers by closing the
// first.
func TestForeignTrack_DialInProgressSurvivesEndOfOldSession(t *testing.T) {
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

	removed := m.removeForeignTrack(stalling, NewRelayTrack())
	require.False(t, removed, "an older track must not remove the track that replaced it")

	m.relayClientsMutex.RLock()
	_, stillTracked := m.relayClients[stalling]
	m.relayClientsMutex.RUnlock()
	require.True(t, stillTracked, "the end of an older session must not remove a track whose dial is still in progress")

	cancel()
	select {
	case <-dialDone:
	case <-time.After(5 * time.Second):
		t.Fatal("openConnVia did not return after context cancellation")
	}
}
