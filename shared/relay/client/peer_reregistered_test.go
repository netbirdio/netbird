package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/relay/server"
)

// When the remote peer registers on the relay again, for example after it restarted
// while its previous registration was still held by the server, an open connection to
// it stays usable and reports the new registration.
func TestConnReportsPeerReregistration(t *testing.T) {
	ctx := context.Background()
	serverListenAddr := "127.0.0.1:51101"
	serverCfg := newClientTestServerConfig(serverListenAddr)

	srv, err := server.NewServer(serverCfg)
	require.NoError(t, err)
	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(server.ListenerConfig{Address: serverListenAddr}); err != nil {
			errChan <- err
		}
	}()
	t.Cleanup(func() {
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	})
	require.NoError(t, waitForServerToStart(errChan))

	clientAlice := NewClient(serverCfg.ExposedAddress, hmacTokenStore, "alice", iface.DefaultMTU)
	require.NoError(t, clientAlice.Connect(ctx))
	t.Cleanup(func() { _ = clientAlice.Close() })

	oldBob := NewClient(serverCfg.ExposedAddress, hmacTokenStore, "bob", iface.DefaultMTU)
	require.NoError(t, oldBob.Connect(ctx))
	t.Cleanup(func() { _ = oldBob.Close() })

	connAliceToBob, err := clientAlice.OpenConn(ctx, "bob")
	require.NoError(t, err)

	select {
	case <-connAliceToBob.PeerReregistered():
		require.FailNow(t, "the first registration must not be reported as a new one")
	case <-time.After(500 * time.Millisecond):
	}

	// Bob comes back with a new relay client while the server still holds the old
	// registration, which the new one replaces.
	newBob := NewClient(serverCfg.ExposedAddress, hmacTokenStore, "bob", iface.DefaultMTU)
	require.NoError(t, newBob.Connect(ctx))
	t.Cleanup(func() { _ = newBob.Close() })

	select {
	case <-connAliceToBob.PeerReregistered():
	case <-time.After(5 * time.Second):
		require.FailNow(t, "the new registration of bob was not reported")
	}
	assert.NoError(t, connAliceToBob.Context().Err(), "the connection to bob should stay open")

	connBobToAlice, err := newBob.OpenConn(ctx, "alice")
	require.NoError(t, err)

	payload := "hello again"
	_, err = connAliceToBob.Write([]byte(payload))
	require.NoError(t, err)
	buf := make([]byte, 1024)
	n, err := connBobToAlice.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, payload, string(buf[:n]), "bob's new registration should receive alice's traffic")
}
