package client

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

func startStaleTestRelay(t *testing.T, address string) server.ListenerConfig {
	t.Helper()

	cfg := server.ListenerConfig{Address: address}
	srv, err := server.NewServer(newManagerTestServerConfig(address))
	require.NoError(t, err)

	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(cfg); err != nil {
			errChan <- err
		}
	}()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	require.NoError(t, waitForServerToStart(errChan))
	return cfg
}

func serveStaleTestManager(t *testing.T, ctx context.Context, peerID string, relay server.ListenerConfig) *Manager {
	t.Helper()

	m := NewManager(ctx, toURL(relay), peerID, iface.DefaultMTU)
	require.NoError(t, m.Serve())
	return m
}

func isClosed(conn *Conn) bool {
	select {
	case <-conn.Context().Done():
		return true
	default:
		return false
	}
}

// A peer first reached through relay R1 that is later reached through R2 has
// restarted onto R2: the R1 connection is dead and must be released.
func TestOpenConn_ClosesStaleConnOnOtherRelay(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	r1 := startStaleTestRelay(t, "localhost:52301")
	r2 := startStaleTestRelay(t, "localhost:52302")

	alice := serveStaleTestManager(t, ctx, "alice", r1)
	serveStaleTestManager(t, ctx, "bob", r1)
	serveStaleTestManager(t, ctx, "carol", r1)
	bobOnR2 := serveStaleTestManager(t, ctx, "bob", r2)
	bobR2Addr, _, err := bobOnR2.RelayInstanceAddress()
	require.NoError(t, err)
	r1Addr, _, err := alice.RelayInstanceAddress()
	require.NoError(t, err)

	viaR1, err := alice.OpenConn(ctx, r1Addr, "bob", netip.Addr{})
	require.NoError(t, err)
	carolConn, err := alice.OpenConn(ctx, r1Addr, "carol", netip.Addr{})
	require.NoError(t, err)

	viaR2, err := alice.OpenConn(ctx, bobR2Addr, "bob", netip.Addr{})
	require.NoError(t, err)

	assert.True(t, isClosed(viaR1), "the connection to the peer on the previous relay must be closed")
	assert.False(t, isClosed(viaR2), "the new connection must stay open")
	assert.False(t, isClosed(carolConn), "an unrelated peer's connection on the same relay must be untouched")
	alice.relayClient.mu.Lock()
	_, tracked := alice.relayClient.conns[messages.HashID("bob")]
	alice.relayClient.mu.Unlock()
	assert.False(t, tracked, "the home client must no longer track the peer")
}

// The same cleanup applies when the peer moves from a foreign relay to the home relay.
func TestOpenConn_ClosesStaleForeignConnWhenPeerReturnsHome(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	r1 := startStaleTestRelay(t, "localhost:52311")
	r2 := startStaleTestRelay(t, "localhost:52312")

	alice := serveStaleTestManager(t, ctx, "alice", r1)
	serveStaleTestManager(t, ctx, "bob", r1)
	bobOnR2 := serveStaleTestManager(t, ctx, "bob", r2)
	bobR2Addr, _, err := bobOnR2.RelayInstanceAddress()
	require.NoError(t, err)
	r1Addr, _, err := alice.RelayInstanceAddress()
	require.NoError(t, err)

	viaR2, err := alice.OpenConn(ctx, bobR2Addr, "bob", netip.Addr{})
	require.NoError(t, err)
	viaR1, err := alice.OpenConn(ctx, r1Addr, "bob", netip.Addr{})
	require.NoError(t, err)

	assert.True(t, isClosed(viaR2), "the foreign relay connection must be closed")
	assert.False(t, isClosed(viaR1), "the home relay connection must stay open")
}

// A failed dial through the new relay must not discard the working connection.
func TestOpenConn_KeepsConnWhenOpenOnOtherRelayFails(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	r1 := startStaleTestRelay(t, "localhost:52321")
	r2 := startStaleTestRelay(t, "localhost:52322")

	alice := serveStaleTestManager(t, ctx, "alice", r1)
	serveStaleTestManager(t, ctx, "bob", r1)
	// A peer on R2 so the R2 address is known, but not bob.
	other := serveStaleTestManager(t, ctx, "other", r2)
	r2Addr, _, err := other.RelayInstanceAddress()
	require.NoError(t, err)
	r1Addr, _, err := alice.RelayInstanceAddress()
	require.NoError(t, err)

	viaR1, err := alice.OpenConn(ctx, r1Addr, "bob", netip.Addr{})
	require.NoError(t, err)

	failCtx, failCancel := context.WithTimeout(ctx, 2*time.Second)
	t.Cleanup(failCancel)
	_, err = alice.OpenConn(failCtx, r2Addr, "bob", netip.Addr{})
	require.Error(t, err)

	assert.False(t, isClosed(viaR1), "the connection must survive a failed open on another relay")
}

// Opening the same peer again on the same relay is rejected and leaves the
// existing connection in place.
func TestOpenConn_SameRelayKeepsExistingConn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	r1 := startStaleTestRelay(t, "localhost:52331")

	alice := serveStaleTestManager(t, ctx, "alice", r1)
	serveStaleTestManager(t, ctx, "bob", r1)
	r1Addr, _, err := alice.RelayInstanceAddress()
	require.NoError(t, err)

	first, err := alice.OpenConn(ctx, r1Addr, "bob", netip.Addr{})
	require.NoError(t, err)

	_, err = alice.OpenConn(ctx, r1Addr, "bob", netip.Addr{})
	require.True(t, errors.Is(err, ErrConnAlreadyExists), "got %v", err)

	assert.False(t, isClosed(first), "the existing connection must stay open")
}
