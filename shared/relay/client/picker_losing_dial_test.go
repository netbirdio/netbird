package client

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/relay/server"
)

// A relay dial that loses the race must stop once a home relay is chosen.
// Finishing it registers the peer on that relay, replacing any registration
// the peer still holds there, and the immediate close that follows is reported
// to the peer's subscribers as the peer going offline.
func TestServerPicker_AbortsLosingDials(t *testing.T) {
	ctx := context.Background()

	fastCfg := server.ListenerConfig{Address: "localhost:52171"}
	srv, err := server.NewServer(newManagerTestServerConfig(fastCfg.Address))
	require.NoError(t, err)
	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(fastCfg); err != nil {
			errChan <- err
		}
	}()
	t.Cleanup(func() {
		if err := srv.Shutdown(ctx); err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	})
	require.NoError(t, waitForServerToStart(errChan))

	// The slow relay accepts the TCP connection and never answers, so the dial
	// to it is still in progress when the fast relay wins.
	slow, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = slow.Close() })
	accepted := make(chan net.Conn, 4)
	slowDialled := make(chan struct{})
	go func() {
		for n := 1; ; n++ {
			c, err := slow.Accept()
			if err != nil {
				return
			}
			accepted <- c
			if n == 2 {
				close(slowDialled)
			}
		}
	}()

	// The fast relay is reached through a gate that holds its connections until
	// both slow dials have connected, so they are always in flight when the fast
	// one wins.
	fastAddr := gateUntil(t, fastCfg.Address, slowDialled)

	sp := ServerPicker{
		TokenStore:        hmacTokenStore,
		PeerID:            "alice",
		MTU:               iface.DefaultMTU,
		ConnectionTimeout: 30 * time.Second,
	}
	// The slow relay is listed twice: each attempt must be aborted on its own.
	slowURL := "rel://" + slow.Addr().String()
	sp.ServerURLs.Store([]string{"rel://" + fastAddr, slowURL, slowURL})

	client, err := sp.PickServer(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	for i := 0; i < 2; i++ {
		var held net.Conn
		select {
		case held = <-accepted:
		case <-time.After(5 * time.Second):
			require.FailNow(t, "the slow relay was not dialled twice")
		}
		t.Cleanup(func() { _ = held.Close() })

		// Drain the WebSocket upgrade request; the client must then hang up rather
		// than keep waiting for an answer.
		require.NoError(t, held.SetReadDeadline(time.Now().Add(3*time.Second)))
		buf := make([]byte, 4096)
		for {
			if _, err = held.Read(buf); err != nil {
				break
			}
		}
		assert.False(t, errors.Is(err, os.ErrDeadlineExceeded), "losing dial %d should be aborted once a home relay is chosen, got: %v", i, err)
	}
}

// gateUntil listens on a local port and forwards each connection to target once
// open is closed.
func gateUntil(t *testing.T, target string, open <-chan struct{}) string {
	t.Helper()
	gate, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = gate.Close() })

	go func() {
		for {
			in, err := gate.Accept()
			if err != nil {
				return
			}
			go func() {
				defer in.Close()
				select {
				case <-open:
				case <-time.After(5 * time.Second):
					return
				}
				out, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer out.Close()
				go func() { _, _ = io.Copy(out, in) }()
				_, _ = io.Copy(in, out)
			}()
		}
	}()
	return gate.Addr().String()
}

// trackingCtx counts the child contexts that register on it and how many of them
// were released, through the AfterFunc hook context.WithCancel uses for parents
// that provide one.
type trackingCtx struct {
	context.Context
	mu         sync.Mutex
	registered int
	released   int
}

func (c *trackingCtx) AfterFunc(f func()) func() bool {
	c.mu.Lock()
	c.registered++
	c.mu.Unlock()
	stop := context.AfterFunc(c.Context, f)
	return func() bool {
		c.mu.Lock()
		c.released++
		c.mu.Unlock()
		return stop()
	}
}

// Value hides the embedded cancel context, which context.WithCancel would otherwise
// find and attach children to directly, bypassing AfterFunc.
func (c *trackingCtx) Value(any) any { return nil }

func (c *trackingCtx) pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.registered - c.released
}

// The chosen relay client runs on a context derived from the picker's parent, which
// lives as long as the relay manager. Closing the client must release that context,
// otherwise every reconnect of the home relay leaves one behind.
func TestServerPicker_ReleasesWinnerContextOnClose(t *testing.T) {
	cfg := server.ListenerConfig{Address: "localhost:52172"}
	srv, err := server.NewServer(newManagerTestServerConfig(cfg.Address))
	require.NoError(t, err)
	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(cfg); err != nil {
			errChan <- err
		}
	}()
	t.Cleanup(func() {
		if err := srv.Shutdown(context.Background()); err != nil {
			t.Errorf("failed to close server: %s", err)
		}
	})
	require.NoError(t, waitForServerToStart(errChan))

	sp := ServerPicker{
		TokenStore:        hmacTokenStore,
		PeerID:            "alice",
		MTU:               iface.DefaultMTU,
		ConnectionTimeout: 30 * time.Second,
	}
	sp.ServerURLs.Store([]string{"rel://" + cfg.Address})

	// The parent needs a non-nil Done, or children never register on it.
	base, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	parent := &trackingCtx{Context: base}
	client, err := sp.PickServer(parent)
	require.NoError(t, err)
	assert.Equal(t, 1, parent.pending(), "only the chosen client's context should stay registered while it runs")

	require.NoError(t, client.Close())
	assert.Equal(t, 0, parent.pending(), "closing the chosen client should release its context")
}
