package client

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/netevents/sweep"
	"github.com/netbirdio/netbird/relay/server"
)

const lifecycleTestTimeout = 15 * time.Second

// stubNetEvents lets a test step the guard: quick reconnects pass without the
// production settle delay, or park until the manager context ends.
type stubNetEvents struct {
	dials atomic.Int32

	mu      sync.Mutex
	hold    bool
	entered chan struct{}
}

// relayProxy forwards TCP connections to a relay server and counts them, so a
// test can see every connection a manager holds, including ones it lost track of.
// While paused it accepts connections without forwarding them, which keeps a
// relay handshake in flight for as long as the test needs.
type relayProxy struct {
	addr   string
	target string

	mu       sync.Mutex
	live     map[net.Conn]struct{}
	accepted int
	resumed  chan struct{}
}

func newStubNetEvents() *stubNetEvents {
	return &stubNetEvents{entered: make(chan struct{}, 8)}
}

func startRelayProxy(t *testing.T, target string) *relayProxy {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "listen for the relay proxy")

	resumed := make(chan struct{})
	close(resumed)
	p := &relayProxy{
		addr:    ln.Addr().String(),
		target:  target,
		live:    make(map[net.Conn]struct{}),
		resumed: resumed,
	}
	go p.serve(ln)
	t.Cleanup(func() {
		_ = ln.Close()
		p.closeAll()
	})
	return p
}

func (n *stubNetEvents) Wait(context.Context) (bool, error) {
	return false, nil
}

func (n *stubNetEvents) IsOnline() bool {
	return true
}

func (n *stubNetEvents) WaitSettled(ctx context.Context, _, _ time.Duration) bool {
	n.mu.Lock()
	hold := n.hold
	n.mu.Unlock()
	if !hold {
		return ctx.Err() == nil
	}

	n.entered <- struct{}{}
	<-ctx.Done()
	return false
}

func (n *stubNetEvents) StartDial(ctx context.Context) *sweep.Dial {
	n.dials.Add(1)
	return (*sweep.Sweeper)(nil).StartDial(ctx)
}

func (n *stubNetEvents) holdQuickReconnect() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.hold = true
}

func (p *relayProxy) serve(ln net.Listener) {
	for {
		client, err := ln.Accept()
		if err != nil {
			return
		}

		p.mu.Lock()
		p.accepted++
		p.live[client] = struct{}{}
		resumed := p.resumed
		p.mu.Unlock()

		go p.pipe(client, resumed)
	}
}

func (p *relayProxy) pipe(client net.Conn, resumed <-chan struct{}) {
	defer func() {
		_ = client.Close()
		p.mu.Lock()
		delete(p.live, client)
		p.mu.Unlock()
	}()

	<-resumed
	upstream, err := net.Dial("tcp", p.target)
	if err != nil {
		return
	}
	defer func() {
		_ = upstream.Close()
	}()

	done := make(chan struct{}, 2)
	forward := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go forward(upstream, client)
	go forward(client, upstream)
	<-done
}

func (p *relayProxy) pause() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.resumed = make(chan struct{})
}

func (p *relayProxy) resume() {
	p.mu.Lock()
	defer p.mu.Unlock()
	close(p.resumed)
}

func (p *relayProxy) closeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for conn := range p.live {
		_ = conn.Close()
	}
}

func (p *relayProxy) liveConns() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.live)
}

func (p *relayProxy) acceptedConns() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.accepted
}

func TestHomeSessionDroppedBeforeAdoption(t *testing.T) {
	tests := []struct {
		name    string
		acquire func(t *testing.T, m *Manager) *session
	}{
		{
			name: "initial pick",
			acquire: func(t *testing.T, m *Manager) *session {
				s, err := m.serverPicker.Pick(m.ctx)
				require.NoError(t, err, "pick the home server")
				return s
			},
		},
		{
			name: "quick reconnect",
			acquire: func(t *testing.T, m *Manager) *session {
				first, err := m.serverPicker.Pick(m.ctx)
				require.NoError(t, err, "pick the home server")
				dropSession(t, first)

				s := m.reconnectGuard.Reconnect(m.ctx, first.client)
				require.NotNil(t, s, "the guard must reconnect")
				require.Same(t, first.client, s.client, "a quick reconnect must reuse the client")
				return s
			},
		},
		{
			name: "server picked by the guard",
			acquire: func(t *testing.T, m *Manager) *session {
				s := m.reconnectGuard.Reconnect(m.ctx, nil)
				require.NotNil(t, s, "the guard must pick a server")
				return s
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			relay := startRelayServer(t)
			bob := serveManager(t, ctx, relay, "bob")
			alice := NewManager(ctx, toURL(relay), "alice", iface.DefaultMTU, WithNetEvents(newStubNetEvents()))

			reconnected := make(chan struct{}, 1)
			alice.SetOnReconnectedListener(func() {
				select {
				case reconnected <- struct{}{}:
				default:
				}
			})

			s := tt.acquire(t, alice)
			dropSession(t, s)

			// Serve hands the picked session over the same way: adopt, then supervise.
			alice.adoptHome(s)
			go alice.superviseHome(s)

			require.NoError(t, waitForReady(ctx, alice, lifecycleTestTimeout), "the manager must recover a home session that ended before it was adopted")
			assert.Same(t, s.client, homeSession(t, alice).client, "the recovery must reuse the client through a quick reconnect")

			select {
			case <-reconnected:
			case <-time.After(lifecycleTestTimeout):
				t.Fatal("the reconnect listener was not called after the recovery")
			}

			relayAddr, _, err := alice.RelayInstanceAddress()
			require.NoError(t, err, "home relay address after the recovery")
			assertRelayedTraffic(t, ctx, alice, bob, relayAddr)
		})
	}
}

func TestHomeSessionDroppedBetweenPublishAndObserve(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	relay := startRelayServer(t)
	bob := serveManager(t, ctx, relay, "bob")
	alice := NewManager(ctx, toURL(relay), "alice", iface.DefaultMTU, WithNetEvents(newStubNetEvents()))

	s, err := alice.serverPicker.Pick(ctx)
	require.NoError(t, err, "pick the home server")

	alice.adoptHome(s)
	dropSession(t, s)
	go alice.superviseHome(s)

	require.NoError(t, waitForReady(ctx, alice, lifecycleTestTimeout), "the manager must recover a home session that ended before the supervisor observed it")

	relayAddr, _, err := alice.RelayInstanceAddress()
	require.NoError(t, err, "home relay address after the recovery")
	assertRelayedTraffic(t, ctx, alice, bob, relayAddr)
}

func TestHomeSessionDroppedWhileAdoptionIsBlocked(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	relay := startRelayServer(t)
	bob := serveManager(t, ctx, relay, "bob")
	alice := serveManager(t, ctx, relay, "alice", WithNetEvents(newStubNetEvents()))

	first := homeSession(t, alice)
	home := first.client

	// The supervisor publishes a session under relayClientMu, so holding the lock
	// keeps the reconnected session unadopted until it has ended.
	alice.relayClientMu.RLock()
	dropSession(t, first)

	var second *session
	reconnected := assert.Eventually(t, func() bool {
		second = home.currentSession()
		return second != nil
	}, lifecycleTestTimeout, 5*time.Millisecond, "the quick reconnect did not establish a new session")
	if reconnected {
		dropSession(t, second)
	}
	alice.relayClientMu.RUnlock()
	require.True(t, reconnected)

	require.NoError(t, waitForReady(ctx, alice, lifecycleTestTimeout), "the manager must recover a reconnected session that ended before it was adopted")

	relayAddr, _, err := alice.RelayInstanceAddress()
	require.NoError(t, err, "home relay address after the recovery")
	assertRelayedTraffic(t, ctx, alice, bob, relayAddr)
}

func TestHomeRecoversOnNewServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	oldRelay := startRelayServer(t)
	newRelay := startRelayServer(t)
	bob := serveManager(t, ctx, newRelay, "bob")
	alice := NewManager(ctx, toURL(oldRelay), "alice", iface.DefaultMTU, WithNetEvents(newStubNetEvents()))

	s, err := alice.serverPicker.Pick(ctx)
	require.NoError(t, err, "pick the home server")
	dropSession(t, s)

	// The old server is no longer a valid home, so the guard cannot reconnect
	// the client it holds and has to pick a server again.
	alice.UpdateServerURLs(toURL(newRelay))

	alice.adoptHome(s)
	go alice.superviseHome(s)

	require.NoError(t, waitForReady(ctx, alice, lifecycleTestTimeout), "the manager must recover on a newly picked server")
	recovered := homeSession(t, alice)
	assert.NotSame(t, s.client, recovered.client, "the recovery must go through a newly picked client")
	assert.Equal(t, toURL(newRelay)[0], recovered.client.connectionURL, "the recovered home must be the new server")

	relayAddr, _, err := alice.RelayInstanceAddress()
	require.NoError(t, err, "home relay address after the recovery")
	assertRelayedTraffic(t, ctx, alice, bob, relayAddr)
}

func TestHomeSupervisorIsSerialAndStopsOnCancel(t *testing.T) {
	tests := []struct {
		name string
		// stop cancels the manager and returns once every session it knows of has ended.
		stop func(t *testing.T, events *stubNetEvents, s *session, cancel context.CancelFunc)
	}{
		{
			name: "cancelled while connected",
			stop: func(t *testing.T, _ *stubNetEvents, s *session, cancel context.CancelFunc) {
				cancel()
				waitCtx, stopWaiting := context.WithTimeout(context.Background(), lifecycleTestTimeout)
				defer stopWaiting()
				require.True(t, s.Wait(waitCtx), "the home session did not end after the manager was cancelled")
			},
		},
		{
			name: "cancelled while reconnecting",
			stop: func(t *testing.T, events *stubNetEvents, s *session, cancel context.CancelFunc) {
				// Park the next reconnect inside the guard, before it dials.
				events.holdQuickReconnect()
				dropSession(t, s)
				select {
				case <-events.entered:
				case <-time.After(lifecycleTestTimeout):
					t.Fatal("the guard did not start a reconnect after the session ended")
				}
				cancel()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The proxy forwards TCP only, so keep the relay client off QUIC.
			t.Setenv(EnvRelayTransport, string(TransportModeWS))

			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			relay := startRelayServer(t)
			proxy := startRelayProxy(t, relay.Address)
			events := newStubNetEvents()
			m := NewManager(ctx, []string{"rel://" + proxy.addr}, "alice", iface.DefaultMTU, WithNetEvents(events))

			s, err := m.serverPicker.Pick(ctx)
			require.NoError(t, err, "pick the home server")
			m.adoptHome(s)

			supervisorDone := make(chan struct{})
			go func() {
				defer close(supervisorDone)
				m.superviseHome(s)
			}()

			const drops = 3
			for i := 1; i <= drops; i++ {
				dropSession(t, s)
				s = nextHomeSession(t, m, s)

				assert.EqualValues(t, i+1, events.dials.Load(), "every recovery must dial exactly once")
				require.Eventually(t, func() bool {
					return proxy.liveConns() == 1
				}, lifecycleTestTimeout, 5*time.Millisecond, "exactly one home connection must stay open after a recovery")
			}

			tt.stop(t, events, s, cancel)

			select {
			case <-supervisorDone:
			case <-time.After(lifecycleTestTimeout):
				t.Fatal("the home supervisor did not stop after the manager was cancelled")
			}

			assert.EqualValues(t, drops+1, events.dials.Load(), "no connection attempt may start after the manager is cancelled")
			assert.Equal(t, drops+1, proxy.acceptedConns(), "the relay must have seen one connection per session")
			require.Eventually(t, func() bool {
				return proxy.liveConns() == 0
			}, lifecycleTestTimeout, 5*time.Millisecond, "no home connection may outlive the manager")
		})
	}
}

func TestForeignSessionEndRemovesTrack(t *testing.T) {
	tests := []struct {
		name string
		drop func(t *testing.T, ctx context.Context, alice *Manager, bobsRelay string)
	}{
		{
			name: "session ends before the track is published",
			drop: func(t *testing.T, ctx context.Context, alice *Manager, bobsRelay string) {
				rt := NewRelayTrack()
				alice.relayClientsMutex.Lock()
				alice.relayClients[bobsRelay] = rt
				alice.relayClientsMutex.Unlock()

				foreign := NewClient(bobsRelay, alice.tokenStore, alice.peerID, alice.mtu)
				s, err := foreign.ConnectSession(ctx)
				require.NoError(t, err, "connect to the foreign relay")
				dropSession(t, s)

				alice.publishForeignSession(bobsRelay, rt, s)
			},
		},
		{
			name: "session ends after the track is published",
			drop: func(t *testing.T, ctx context.Context, alice *Manager, bobsRelay string) {
				_, err := alice.OpenConn(ctx, bobsRelay, "bob", netip.Addr{})
				require.NoError(t, err, "alice must reach bob over bob's relay")

				dropSession(t, trackSession(t, foreignTrack(t, alice, bobsRelay)))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)

			bob := serveManager(t, ctx, startRelayServer(t), "bob")
			alice := NewManager(ctx, toURL(startRelayServer(t)), "alice", iface.DefaultMTU)
			// Keep the idle cleanup out of the way: the track must go on its own.
			alice.cleanupInterval = time.Hour
			require.NoError(t, alice.Serve(), "serve manager of alice")

			bobsRelay, _, err := bob.RelayInstanceAddress()
			require.NoError(t, err, "bob's relay address")

			tt.drop(t, ctx, alice, bobsRelay)

			require.Eventually(t, func() bool {
				alice.relayClientsMutex.RLock()
				defer alice.relayClientsMutex.RUnlock()
				_, tracked := alice.relayClients[bobsRelay]
				return !tracked
			}, lifecycleTestTimeout, 5*time.Millisecond, "the track of an ended foreign session must be removed without the idle cleanup")

			assertRelayedTraffic(t, ctx, alice, bob, bobsRelay)
			assert.True(t, trackSession(t, foreignTrack(t, alice, bobsRelay)).client.Ready(), "the next OpenConn must run on a fresh foreign connection")
		})
	}
}

func startRelayServer(t *testing.T) server.ListenerConfig {
	t.Helper()

	address, _ := freeAddr(t)
	cfg := server.ListenerConfig{Address: address}
	srv, err := server.NewServer(newManagerTestServerConfig(cfg.Address))
	require.NoError(t, err, "create relay server")

	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(cfg); err != nil {
			errChan <- err
		}
	}()
	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
	})
	require.NoError(t, waitForServerToStart(errChan), "start relay server")
	return cfg
}

func serveManager(t *testing.T, ctx context.Context, relay server.ListenerConfig, peerID string, opts ...ManagerOption) *Manager {
	t.Helper()

	m := NewManager(ctx, toURL(relay), peerID, iface.DefaultMTU, opts...)
	require.NoError(t, m.Serve(), "serve manager of %s", peerID)
	return m
}

func homeSession(t *testing.T, m *Manager) *session {
	t.Helper()

	m.relayClientMu.RLock()
	home := m.relayClient
	m.relayClientMu.RUnlock()
	require.NotNil(t, home, "the manager has no home relay client")

	s := home.currentSession()
	require.NotNil(t, s, "the home relay client has no session")
	return s
}

func nextHomeSession(t *testing.T, m *Manager, prev *session) *session {
	t.Helper()

	var next *session
	require.Eventually(t, func() bool {
		m.relayClientMu.RLock()
		home := m.relayClient
		m.relayClientMu.RUnlock()

		next = home.currentSession()
		return next != nil && next != prev
	}, lifecycleTestTimeout, 5*time.Millisecond, "the manager did not establish a new home session")
	return next
}

func foreignTrack(t *testing.T, m *Manager, serverAddress string) *RelayTrack {
	t.Helper()

	m.relayClientsMutex.RLock()
	rt, tracked := m.relayClients[serverAddress]
	m.relayClientsMutex.RUnlock()
	require.True(t, tracked, "the foreign relay %s must be tracked", serverAddress)
	return rt
}

func trackSession(t *testing.T, rt *RelayTrack) *session {
	t.Helper()

	rt.RLock()
	relayClient := rt.relayClient
	rt.RUnlock()
	require.NotNil(t, relayClient, "the foreign relay track has no client")

	s := relayClient.currentSession()
	require.NotNil(t, s, "the foreign relay client has no session")
	return s
}

func assertRelayedTraffic(t *testing.T, ctx context.Context, sender, receiver *Manager, relayAddr string) {
	t.Helper()

	out, err := sender.OpenConn(ctx, relayAddr, receiver.peerID, netip.Addr{})
	require.NoError(t, err, "open the relayed connection from %s", sender.peerID)
	in, err := receiver.OpenConn(ctx, relayAddr, sender.peerID, netip.Addr{})
	require.NoError(t, err, "open the relayed connection from %s", receiver.peerID)

	payload := []byte("ping over the relay")
	_, err = out.Write(payload)
	require.NoError(t, err, "write to the relayed connection")

	received := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 2*len(payload))
		n, err := in.Read(buf)
		if err != nil {
			received <- nil
			return
		}
		received <- buf[:n]
	}()

	select {
	case got := <-received:
		assert.Equal(t, payload, got, "the payload must arrive over the relay")
	case <-time.After(lifecycleTestTimeout):
		t.Fatal("no payload arrived over the relay")
	}
}
