package client

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	relayAuth "github.com/netbirdio/netbird/shared/relay/auth/hmac"
)

func TestServerPicker_UnavailableServers(t *testing.T) {
	timeout := 5 * time.Second
	sp := ServerPicker{
		TokenStore:        nil,
		PeerID:            "test",
		ConnectionTimeout: timeout,
	}
	sp.ServerURLs.Store([]string{"rel://dummy1", "rel://dummy2"})

	ctx, cancel := context.WithTimeout(context.Background(), timeout+1)
	defer cancel()

	go func() {
		_, err := sp.Pick(ctx)
		if err == nil {
			t.Error(err)
		}
		cancel()
	}()

	<-ctx.Done()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Errorf("Pick() took too long to complete")
	}
}

func TestServerPicker_ClosesLosingSessions(t *testing.T) {
	// The proxies forward TCP only, so keep the relay client off QUIC.
	t.Setenv(EnvRelayTransport, string(TransportModeWS))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	proxies := []*relayProxy{
		startRelayProxy(t, startRelayServer(t).Address),
		startRelayProxy(t, startRelayServer(t).Address),
	}
	sp := &ServerPicker{
		TokenStore:        &relayAuth.TokenStore{},
		PeerID:            "alice",
		ConnectionTimeout: lifecycleTestTimeout,
	}
	sp.ServerURLs.Store([]string{"rel://" + proxies[0].addr, "rel://" + proxies[1].addr})

	winner, err := sp.Pick(ctx)
	require.NoError(t, err, "pick a server")

	require.Eventually(t, func() bool {
		return proxies[0].liveConns()+proxies[1].liveConns() == 1
	}, lifecycleTestTimeout, 5*time.Millisecond, "the picker must close every session it did not hand over")

	assert.False(t, winner.isClosed(), "the picker must keep the session it handed over")
}

func TestServerPicker_ClosesSessionNobodyTook(t *testing.T) {
	// The proxy forwards TCP only, so keep the relay client off QUIC.
	t.Setenv(EnvRelayTransport, string(TransportModeWS))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	proxy := startRelayProxy(t, startRelayServer(t).Address)
	sp := &ServerPicker{
		TokenStore:        &relayAuth.TokenStore{},
		PeerID:            "alice",
		ConnectionTimeout: 200 * time.Millisecond,
	}
	sp.ServerURLs.Store([]string{"rel://" + proxy.addr})

	// The paused proxy keeps the handshake in flight past the pick timeout, so
	// the connection can only complete after the caller has given up.
	proxy.pause()
	_, err := sp.Pick(ctx)
	require.Error(t, err, "the pick must give up while the handshake is held")
	require.Eventually(t, func() bool {
		return proxy.liveConns() == 1
	}, lifecycleTestTimeout, 5*time.Millisecond, "the candidate must still be connecting after the pick gave up")
	proxy.resume()

	require.Eventually(t, func() bool {
		return proxy.liveConns() == 0
	}, lifecycleTestTimeout, 5*time.Millisecond, "a session that connects after the pick gave up must be closed")
	assert.Equal(t, 1, proxy.acceptedConns(), "the candidate must have dialed once")
}
