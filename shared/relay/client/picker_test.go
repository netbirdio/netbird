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
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	sp := &ServerPicker{
		TokenStore:        &relayAuth.TokenStore{},
		PeerID:            "alice",
		ConnectionTimeout: lifecycleTestTimeout,
	}
	urls := []string{"rel://" + startRelayServer(t).Address, "rel://" + startRelayServer(t).Address}

	// Both candidates connect before the picker sees any result. A candidate
	// that never became a session cannot stand in for one the picker closed.
	results := make(chan connResult, len(urls))
	sessions := make([]*session, 0, len(urls))
	for _, url := range urls {
		connected := make(chan connResult, 1)
		sp.startConnection(ctx, connected, url)
		cr := <-connected
		require.NoError(t, cr.Err, "connect to %s", url)
		sessions = append(sessions, cr.Session)
		results <- cr
	}

	picked := make(chan connResult)
	go sp.processConnResults(ctx, results, picked)

	var winner connResult
	select {
	case winner = <-picked:
	case <-time.After(lifecycleTestTimeout):
		t.Fatal("the picker did not hand over a session")
	}
	require.Same(t, sessions[0], winner.Session, "the first connected candidate must be handed over")

	waitCtx, cancelWait := context.WithTimeout(ctx, lifecycleTestTimeout)
	t.Cleanup(cancelWait)
	assert.True(t, sessions[1].Wait(waitCtx), "the picker must close the session it did not hand over")
	assert.False(t, sessions[0].isClosed(), "the picker must keep the session it handed over")
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
