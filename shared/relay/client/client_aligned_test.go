package client

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/keepalive"
	"github.com/netbirdio/netbird/shared/peerauth"
	auth "github.com/netbirdio/netbird/shared/relay/auth/hmac"
	"github.com/netbirdio/netbird/shared/relay/client/dialer/ws"
	"github.com/netbirdio/netbird/shared/relay/messages"
)

type recordConn struct {
	net.Conn
	mu     sync.Mutex
	writes [][]byte
	closed bool
}

func (c *recordConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), b...))
	return len(b), nil
}

func (c *recordConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *recordConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *recordConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *recordConn) SetDeadline(time.Time) error      { return nil }
func (c *recordConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordConn) SetWriteDeadline(time.Time) error { return nil }
func (c *recordConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (c *recordConn) lastWrite(t *testing.T) []byte {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	require.NotEmpty(t, c.writes, "the connection must have a write")
	return c.writes[len(c.writes)-1]
}

func newAlignedTestClient(t *testing.T, asking bool) *Client {
	t.Helper()
	c := NewClient("rels://relay.example:443", &auth.TokenStore{}, "peer-key", 0)
	c.log = log.WithField("test", "aligned")
	if asking {
		c.alignedRequest = func() (time.Duration, bool) { return alignedhb.DefaultPeriod, true }
	} else {
		c.alignedRequest = func() (time.Duration, bool) { return 0, false }
	}
	return c
}

// newAlignedTestSession returns a session of a new test client on conn, at
// protocol version, with the period the relay confirmed at the handshake.
func newAlignedTestSession(t *testing.T, period time.Duration, conn net.Conn, version messages.ProtocolVersion) *session {
	t.Helper()
	c := newAlignedTestClient(t, period > 0)
	s := newSession(c, conn, &RelayAddr{addr: c.connectionURL}, ws.Network, messages.NewEncoder(version, messages.MaxMessageSize), period)
	t.Cleanup(s.hc.Stop)
	return s
}

// boundTestClient returns a client holding a bound auth token, asking for the aligned
// heartbeat or not.
func boundTestClient(t *testing.T, serverURL string, asking bool) *Client {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	store := &auth.TokenStore{}
	require.NoError(t, store.UpdateAuthToken([]byte("opaque auth token")))
	c := NewClient(serverURL, store, "alice", iface.DefaultMTU)
	c.authKey = priv
	c.alignedRequest = newAlignedTestClient(t, asking).alignedRequest
	return c
}

// handShakeWith runs the client handshake against a scripted relay that answers resp, and
// returns the Auth message the relay read and the period the client accepted.
func handShakeWith(t *testing.T, c *Client, resp []byte) ([]byte, time.Duration) {
	t.Helper()
	clientEnd, relayEnd := net.Pipe()
	t.Cleanup(func() { _ = clientEnd.Close(); _ = relayEnd.Close() })
	authMsg := make(chan []byte, 1)
	go func() {
		buf := make([]byte, messages.MaxHandshakeSize)
		n, err := relayEnd.Read(buf)
		if err != nil {
			close(authMsg)
			return
		}
		authMsg <- buf[:n]
		_, _ = relayEnd.Write(resp)
	}()
	addr, _, period, err := c.handShake(context.Background(), clientEnd)
	require.NoError(t, err, "the handshake must succeed")
	assert.Equal(t, "rels://relay.example.com:443", addr.String(), "the instance URL is read as before")
	msg, ok := <-authMsg
	require.True(t, ok, "the relay must read the Auth message")
	return msg, period
}

// authResponse builds an AuthResponse of version with the extension area ext.
func authResponse(t *testing.T, version messages.ProtocolVersion, ext []byte) []byte {
	t.Helper()
	const instanceURL = "rels://relay.example.com:443"
	enc := messages.NewEncoder(version, messages.MaxMessageSize)
	if version < messages.ProtocolV2 {
		resp, err := enc.AuthResponse(instanceURL)
		require.NoError(t, err)
		return resp
	}
	resp, err := enc.AuthResponseEnvelope(instanceURL, ext)
	require.NoError(t, err)
	return resp
}

// An asking client with a bound token puts the period after the proof and takes the clamped
// period the relay confirms. Any other answer keeps it stock without failing the handshake.
func TestHandShakeAlignedPeriod(t *testing.T) {
	cases := []struct {
		name    string
		version messages.ProtocolVersion
		ext     []byte
		want    time.Duration
	}{
		{"confirmed", messages.ProtocolV2, messages.AppendAlignedHeartbeatEntry(nil, 60), time.Minute},
		{"below the range", messages.ProtocolV2, messages.AppendAlignedHeartbeatEntry(nil, 10), alignedhb.MinPeriod},
		{"above the range", messages.ProtocolV2, messages.AppendAlignedHeartbeatEntry(nil, 1000), alignedhb.MaxPeriod},
		{"after another entry", messages.ProtocolV2, messages.AppendAlignedHeartbeatEntry([]byte{9, 0, 1, 'x'}, 60), time.Minute},
		{"zero period", messages.ProtocolV2, messages.AppendAlignedHeartbeatEntry(nil, 0), 0},
		{"envelope without entry", messages.ProtocolV2, nil, 0},
		{"one byte value", messages.ProtocolV2, []byte{messages.ExtTypeAlignedHeartbeat, 0, 1, 60}, 0},
		{"length beyond the area", messages.ProtocolV2, []byte{messages.ExtTypeAlignedHeartbeat, 0, 9, 0, 60}, 0},
		{"v1 relay", messages.ProtocolV1, nil, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := boundTestClient(t, "rels://relay.example.com:443", true)
			msg, period := handShakeWith(t, c, authResponse(t, tc.version, tc.ext))
			assert.Equal(t, tc.want, period, "accepted period")

			ext, err := messages.UnmarshalAuthExtension(msg)
			require.NoError(t, err)
			_, err = peerauth.UnmarshalRelayExtension(ext)
			assert.NoError(t, err, "the proof stays readable")
			asked, ok, err := messages.AlignedHeartbeatEntry(ext)
			require.NoError(t, err)
			assert.True(t, ok, "the Auth message carries the request")
			assert.Equal(t, uint16(60), asked, "the Auth message carries the asked period")
		})
	}
}

// A client that does not ask (desktop) sends the Auth message of today and ignores a period
// the relay answers anyway.
func TestHandShakeNotAskingStaysStock(t *testing.T) {
	c := boundTestClient(t, "rels://relay.example.com:443", false)
	msg, period := handShakeWith(t, c, authResponse(t, messages.ProtocolV2, messages.AppendAlignedHeartbeatEntry(nil, 60)))
	assert.Zero(t, period, "an answer to no request is ignored")

	ext, err := messages.UnmarshalAuthExtension(msg)
	require.NoError(t, err)
	proof, err := peerauth.UnmarshalRelayExtension(ext)
	require.NoError(t, err)
	proofOnly, err := peerauth.MarshalRelayExtension(proof)
	require.NoError(t, err)
	assert.Equal(t, proofOnly, ext, "the extension area holds only the proof")
}

// A mobile client with a legacy token cannot ask: it sends the v1 Auth message of today and
// stays stock whatever the relay answers.
func TestHandShakeLegacyTokenStaysStock(t *testing.T) {
	store := &auth.TokenStore{}
	require.NoError(t, store.UpdateToken(&auth.Token{Payload: "payload", Signature: "c2ln"}))
	c := NewClient("rels://relay.example.com:443", store, "alice", iface.DefaultMTU)
	c.alignedRequest = newAlignedTestClient(t, true).alignedRequest

	msg, period := handShakeWith(t, c, authResponse(t, messages.ProtocolV1, nil))
	want, err := messages.MarshalAuthMsg(messages.HashID("alice"), store.TokenBinary())
	require.NoError(t, err)
	assert.Equal(t, want, msg, "a legacy token keeps the Auth message of today")
	assert.Zero(t, period, "a legacy token stays stock")
}

// End to end against a relay with this change: the asking bound-token client gets an aligned
// session, the one that does not ask stays stock.
func TestClientAlignedWithRelay(t *testing.T) {
	ctx := context.Background()
	address, _ := freeAddr(t)
	mgmtPub, mgmtKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	keys, err := peerauth.NewEd25519Keys([]ed25519.PublicKey{mgmtPub})
	require.NoError(t, err)
	serverCfg := newClientTestServerConfig(address)
	serverCfg.PeerAuth = server.PeerAuthConfig{Keys: keys}
	srv, err := server.NewServer(serverCfg)
	require.NoError(t, err)
	go func() { _ = srv.Listen(server.ListenerConfig{Address: address}) }()
	t.Cleanup(func() { _ = srv.Shutdown(ctx) })
	require.Eventually(t, func() bool {
		conn, err := net.Dial("tcp", address)
		if err != nil {
			return false
		}
		_ = conn.Close()
		return true
	}, 5*time.Second, 20*time.Millisecond, "relay must start listening")

	connect := func(name string, asking bool) *session {
		wgKey, err := wgtypes.GenerateKey()
		require.NoError(t, err)
		authPub, authKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		token, err := peerauth.IssueEd25519Token(mgmtKey, peerauth.Token{
			Expiry:  time.Now().Add(time.Hour),
			WGPub:   wgKey.PublicKey(),
			AuthPub: authPub,
		})
		require.NoError(t, err)
		store := &auth.TokenStore{}
		require.NoError(t, store.UpdateAuthToken(token))
		c := NewClient(serverCfg.ExposedAddress, store, wgKey.PublicKey().String(), iface.DefaultMTU)
		c.authKey = authKey
		c.alignedRequest = newAlignedTestClient(t, asking).alignedRequest
		require.NoError(t, c.Connect(ctx), "connect %s", name)
		t.Cleanup(func() { _ = c.Close() })
		return c.CurrentSession()
	}

	assert.Equal(t, time.Minute, connect("mobile", true).alignedPeriod, "the relay confirms the asked period")
	assert.Zero(t, connect("desktop", false).alignedPeriod, "a client that does not ask stays stock")
}

// An aligned session waits the aligned receive timeout for server health checks from the
// start, past the stock 35 s.
func TestAlignedSessionReceiveTimeout(t *testing.T) {
	// The timing below expects the default of one failed attempt.
	t.Setenv("NB_RELAY_HC_ATTEMPT_THRESHOLD", "1")
	synctest.Test(t, func(t *testing.T) {
		s := newAlignedTestSession(t, time.Minute, &recordConn{}, messages.ProtocolV2)
		start := time.Now()
		<-s.hc.OnTimeout
		assert.Equal(t, alignedhb.ReceiveTimeout(time.Minute), time.Since(start), "the aligned receive timeout")
	})
	synctest.Test(t, func(t *testing.T) {
		s := newAlignedTestSession(t, 0, &recordConn{}, messages.ProtocolV2)
		start := time.Now()
		<-s.hc.OnTimeout
		assert.Equal(t, 35*time.Second, time.Since(start), "a stock session keeps the stock receive timeout")
	})
}

// Health check answers stay the stock frame of the connection version, aligned or not.
func TestHandleHealthCheckAnswersStockFrame(t *testing.T) {
	for _, period := range []time.Duration{0, time.Minute} {
		for _, version := range []messages.ProtocolVersion{messages.ProtocolV1, messages.ProtocolV2} {
			conn := &recordConn{}
			s := newAlignedTestSession(t, period, conn, version)
			s.handleHealthCheck()
			assert.Equal(t, messages.NewEncoder(version, messages.MaxMessageSize).Healthcheck(), conn.lastWrite(t),
				"period %s, v%d: stock answer", period, version)
		}
	}
}

// An aligned session sets the aligned TCP keepalive on its own connection.
func TestAlignedSessionSetsKeepalive(t *testing.T) {
	if _, err := keepalive.Idle(nil); errors.Is(err, errors.ErrUnsupported) {
		t.Skip(err)
	}
	conn := tcpConn(t)
	stockIdle, err := keepalive.Idle(conn)
	require.NoError(t, err)
	newAlignedTestSession(t, time.Minute, conn, messages.ProtocolV2)

	idle, err := keepalive.Idle(conn)
	require.NoError(t, err)
	assert.Equal(t, keepalive.AlignedConfig(time.Minute).Idle, idle, "the session connection gets the aligned keepalive")
	assert.NotEqual(t, stockIdle, idle, "the keepalive changed from the stock one")
}

// setTestWatcher installs a fresh default hbwatch Watcher for the test.
func setTestWatcher(t *testing.T) *hbwatch.Watcher {
	t.Helper()
	w := hbwatch.New(wallClock{}, time.Minute)
	t.Cleanup(hbwatch.SetDefault(w))
	return w
}

// relayStream returns the hbwatch relay stream, ok false when unregistered.
func relayStream(w *hbwatch.Watcher) (hbwatch.StreamStatus, bool) {
	for _, st := range w.Snapshot().Streams {
		if st.Service == hbwatch.Relay {
			return st, true
		}
	}
	return hbwatch.StreamStatus{}, false
}

func TestGetDialersWSOnlyWhenAligned(t *testing.T) {
	c := newAlignedTestClient(t, true)
	dialers := c.getDialers(TransportModeAuto)
	require.Len(t, dialers, 1, "an aligned mobile client dials WebSocket only")
	assert.IsType(t, ws.Dialer{}, dialers[0], "the only dialer is WebSocket")

	c = newAlignedTestClient(t, false)
	dialers = c.getDialers(TransportModeAuto)
	assert.Len(t, dialers, 2, "a stock client keeps the race dialer")
}

// TestSessionRegistersOnlyWhenWatched checks that a session the manager did
// not adopt as home, such as a foreign or picker-loser session, never
// registers with hbwatch, even with server health checks; startWatch does,
// with the period the relay confirmed at the handshake.
func TestSessionRegistersOnlyWhenWatched(t *testing.T) {
	w := setTestWatcher(t)
	s := newAlignedTestSession(t, time.Minute, &recordConn{}, messages.ProtocolV2)

	s.handleHealthCheck()
	_, registered := relayStream(w)
	assert.False(t, registered, "an unwatched session never registers")

	s.startWatch()
	st, registered := relayStream(w)
	require.True(t, registered, "the session registers at startWatch")
	assert.Equal(t, time.Minute, st.Period, "the registration carries the confirmed period")
	assert.False(t, st.Aligned, "a fresh registration starts unaligned")

	s.handleHealthCheck()
	st, _ = relayStream(w)
	assert.True(t, st.Aligned, "the next server health check reaches hbwatch")
}

// TestStockSessionNeverSeen checks that the health checks of a registered
// stock session never mark the relay stream aligned.
func TestStockSessionNeverSeen(t *testing.T) {
	w := setTestWatcher(t)
	s := newAlignedTestSession(t, 0, &recordConn{}, messages.ProtocolV2)
	s.startWatch()
	s.handleHealthCheck()

	st, registered := relayStream(w)
	require.True(t, registered, "the session registers at startWatch")
	assert.False(t, st.Aligned, "a stock session stays unaligned")
	assert.Zero(t, st.Period, "a stock session has no period")
}

// TestLateWatchAfterReadLoopExitDoesNotRegister covers adoptHome racing the
// read loop exit of the session it adopts: a registration after the exit
// must not stick, so the next session still registers its own connection.
func TestLateWatchAfterReadLoopExitDoesNotRegister(t *testing.T) {
	w := setTestWatcher(t)
	s := newAlignedTestSession(t, time.Minute, &recordConn{}, messages.ProtocolV1)

	// The read loop exits before the late registration.
	s.stopWatch()
	s.startWatch()
	assert.Empty(t, w.Snapshot().Streams, "an ended session must not be registered")

	next := newAlignedTestSession(t, time.Minute, &recordConn{}, messages.ProtocolV1)
	next.startWatch()
	assert.Len(t, w.Snapshot().Streams, 1, "the next session registers")
}

// TestStaleWatchKeepsNewerRegistration covers an old session that ends
// after a newer one registered: its unregister and its last frames must
// neither drop the newer registration nor mark it aligned.
func TestStaleWatchKeepsNewerRegistration(t *testing.T) {
	w := setTestWatcher(t)
	old := newAlignedTestSession(t, time.Minute, &recordConn{}, messages.ProtocolV2)
	old.startWatch()

	current := newAlignedTestSession(t, 0, &recordConn{}, messages.ProtocolV2)
	current.startWatch()

	old.stopWatch()
	old.handleHealthCheck()

	st, registered := relayStream(w)
	require.True(t, registered, "the newer session stays registered")
	assert.False(t, st.Aligned, "a frame of the old session must not mark the newer one aligned")
	assert.Zero(t, st.Period, "a frame of the old session must not set the period")
}

// TestReadLoopExitUnregisters checks that the end of the read loop ends the
// hbwatch registration of its session, so a lost home connection does not
// stay registered until the next session registers.
func TestReadLoopExitUnregisters(t *testing.T) {
	w := setTestWatcher(t)
	clientEnd, serverEnd := net.Pipe()
	s := newAlignedTestSession(t, time.Minute, clientEnd, messages.ProtocolV1)
	s.startWatch()
	_, registered := relayStream(w)
	require.True(t, registered, "the session registers at startWatch")

	require.NoError(t, serverEnd.Close())
	s.ReadLoop()

	_, registered = relayStream(w)
	assert.False(t, registered, "the read loop exit unregisters the session")
}

// TestStaleActionClosesLikeHealthCheckTimeout checks that the hbwatch stale
// action marks the session internally stopped before it closes the
// connection, so the read loop exit is not logged as a server error.
func TestStaleActionClosesLikeHealthCheckTimeout(t *testing.T) {
	conn := &recordConn{}
	s := newAlignedTestSession(t, time.Minute, conn, messages.ProtocolV1)

	s.closeStale()
	assert.True(t, s.internallyStopped.isSet(), "the stale action marks the session internally stopped")
	assert.True(t, conn.isClosed(), "the stale action closes the connection")
}

// TestManagerWatchesOnlyTheHomeSession checks the manager flow: the home
// session registers at adoption, a foreign relay session never takes the
// slot, and after a reconnect the next home session holds the registration.
func TestManagerWatchesOnlyTheHomeSession(t *testing.T) {
	w := setTestWatcher(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	homeRelay := startRelayServer(t)
	foreignRelay := startRelayServer(t)

	// bob waits on the foreign relay through a bare client, which never
	// registers with hbwatch.
	bob := NewClient(toURL(foreignRelay)[0], &auth.TokenStore{}, "bob", iface.DefaultMTU)
	require.NoError(t, bob.Connect(ctx), "connect bob to the foreign relay")
	t.Cleanup(func() { _ = bob.Close() })
	foreignAddr, err := bob.ServerInstanceURL()
	require.NoError(t, err, "foreign relay address")

	alice := NewManager(ctx, toURL(homeRelay), "alice", iface.DefaultMTU, WithNetEvents(newStubNetEvents()))
	require.NoError(t, alice.Serve(), "serve manager of alice")

	st, registered := relayStream(w)
	require.True(t, registered, "the adopted home session registers")
	assert.Equal(t, toURL(homeRelay)[0], st.Addr, "the registration belongs to the home relay")

	_, err = alice.OpenConn(ctx, foreignAddr, "bob", netip.Addr{})
	require.NoError(t, err, "alice must reach bob over the foreign relay")
	require.Len(t, w.Snapshot().Streams, 1, "hbwatch holds one relay stream")
	st, _ = relayStream(w)
	assert.Equal(t, toURL(homeRelay)[0], st.Addr, "a foreign session never takes the registration")

	home := homeSession(t, alice)
	dropSession(t, home)
	next := nextHomeSession(t, alice, home)
	require.Eventually(t, func() bool {
		next.watchMu.Lock()
		defer next.watchMu.Unlock()
		return next.watchStop != nil
	}, lifecycleTestTimeout, 5*time.Millisecond, "the next home session must register")
	_, registered = relayStream(w)
	assert.True(t, registered, "the ended home session must not drop the registration of the next one")
}

// tcpConn returns the client end of a loopback TCP connection.
func tcpConn(t *testing.T) net.Conn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		s, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- s
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	s, ok := <-accepted
	require.True(t, ok, "accept must succeed")
	t.Cleanup(func() { _ = s.Close() })
	return conn
}

type wallClock struct{}

func (wallClock) Now() time.Time                      { return time.Now() }
func (wallClock) AfterFunc(d time.Duration, f func()) { time.AfterFunc(d, f) }
