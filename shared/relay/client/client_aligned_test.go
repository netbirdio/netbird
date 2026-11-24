package client

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/hbwatch"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/shared/alignedhb"
	"github.com/netbirdio/netbird/shared/alignedhb/keepalive"
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

func (c *recordConn) lastWrite() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
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
// protocol version.
func newAlignedTestSession(t *testing.T, asking bool, conn net.Conn, version messages.ProtocolVersion) *session {
	t.Helper()
	c := newAlignedTestClient(t, asking)
	s := newSession(c, conn, &RelayAddr{addr: c.connectionURL}, ws.Network, messages.NewEncoder(version, messages.MaxMessageSize))
	t.Cleanup(s.hc.Stop)
	return s
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
	assert.IsType(t, ws.Dialer{}, dialers[0])

	c = newAlignedTestClient(t, false)
	dialers = c.getDialers(TransportModeAuto)
	assert.Len(t, dialers, 2, "a stock client keeps the race dialer")
}

// TestAskAlignedUsesSessionVersion checks that the period request goes out in
// the protocol version of the connection: the relay drops a frame of another
// version on a V2 connection.
func TestAskAlignedUsesSessionVersion(t *testing.T) {
	for _, version := range []messages.ProtocolVersion{messages.ProtocolV1, messages.ProtocolV2} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			conn := &recordConn{}
			s := newAlignedTestSession(t, true, conn, version)

			s.askAligned()
			require.Len(t, conn.writes, 1, "the asking client writes one request")
			req := conn.lastWrite()
			assert.NoError(t, messages.ValidateConnectionVersion(req, version), "the request carries the session version")
			period, ok, err := messages.UnmarshalHealthcheckPeriod(req)
			require.NoError(t, err)
			assert.True(t, ok, "the request carries a period")
			assert.Equal(t, uint16(60), period, "the request carries the asked period")
		})
	}

	conn := &recordConn{}
	s := newAlignedTestSession(t, false, conn, messages.ProtocolV2)
	s.askAligned()
	assert.Empty(t, conn.writes, "a stock client asks for nothing")
}

func TestHandleHealthCheckAnswersWithPeriod(t *testing.T) {
	for _, version := range []messages.ProtocolVersion{messages.ProtocolV1, messages.ProtocolV2} {
		t.Run(fmt.Sprintf("v%d", version), func(t *testing.T) {
			conn := &recordConn{}
			s := newAlignedTestSession(t, true, conn, version)
			enc := messages.NewEncoder(version, messages.MaxMessageSize)

			// Before the server answers aligned, the answer already carries the
			// requested period, so a server that missed the first frame switches
			// at a later answer.
			s.handleHealthCheck(enc.Healthcheck())
			answer := conn.lastWrite()
			assert.NoError(t, messages.ValidateConnectionVersion(answer, version), "the answer carries the session version")
			period, ok, err := messages.UnmarshalHealthcheckPeriod(answer)
			require.NoError(t, err)
			assert.True(t, ok, "the answer carries a period")
			assert.Equal(t, uint16(60), period, "the answer carries the asked period")
			assert.Zero(t, s.confirmedPeriod(), "not aligned before the server frame")

			// The first server frame with the period switches the session.
			s.handleHealthCheck(enc.HealthcheckWithPeriod(10))
			assert.Equal(t, alignedhb.MinPeriod, s.confirmedPeriod(), "the server period is clamped")

			s.handleHealthCheck(enc.HealthcheckWithPeriod(60))
			answer = conn.lastWrite()
			assert.NoError(t, messages.ValidateConnectionVersion(answer, version), "the answer carries the session version")
			period, ok, err = messages.UnmarshalHealthcheckPeriod(answer)
			require.NoError(t, err)
			assert.True(t, ok, "the answer carries a period")
			assert.Equal(t, uint16(60), period, "answers carry the confirmed period")
		})
	}
}

func TestHandleHealthCheckStockStaysStock(t *testing.T) {
	conn := &recordConn{}
	s := newAlignedTestSession(t, false, conn, messages.ProtocolV1)

	s.handleHealthCheck(messages.MarshalHealthcheck())
	_, ok, err := messages.UnmarshalHealthcheckPeriod(conn.lastWrite())
	require.NoError(t, err)
	assert.False(t, ok, "a stock client answers with the stock frame")
	assert.Zero(t, s.confirmedPeriod())

	// A one-byte payload stays stock and never closes the connection.
	oneByte := append(messages.MarshalHealthcheck(), 0x3c)
	s.handleHealthCheck(oneByte)
	assert.Zero(t, s.confirmedPeriod())
	assert.False(t, conn.isClosed(), "a one-byte payload must not close the connection")
}

// TestSwitchAlignedSetsKeepaliveOnSessionConn checks that the aligned TCP
// keepalive goes on the connection of the session that got the server frame.
func TestSwitchAlignedSetsKeepaliveOnSessionConn(t *testing.T) {
	if _, err := keepalive.Idle(nil); errors.Is(err, errors.ErrUnsupported) {
		t.Skip(err)
	}
	conn := tcpConn(t)
	s := newAlignedTestSession(t, true, conn, messages.ProtocolV1)

	s.handleHealthCheck(messages.MarshalHealthcheckWithPeriod(60))

	idle, err := keepalive.Idle(conn)
	require.NoError(t, err)
	assert.Equal(t, keepalive.AlignedConfig(time.Minute).Idle, idle, "the session connection gets the aligned keepalive")
}

// TestSessionRegistersOnlyWhenWatched checks that a session the manager did
// not adopt as home, such as a foreign or picker-loser session, never
// registers with hbwatch, even with aligned server frames; startWatch does.
func TestSessionRegistersOnlyWhenWatched(t *testing.T) {
	w := setTestWatcher(t)
	conn := &recordConn{}
	s := newAlignedTestSession(t, true, conn, messages.ProtocolV1)

	s.handleHealthCheck(messages.MarshalHealthcheckWithPeriod(60))
	_, registered := relayStream(w)
	assert.False(t, registered, "an unwatched session never registers")

	s.startWatch()
	st, registered := relayStream(w)
	assert.True(t, registered, "the session registers at startWatch")
	assert.False(t, st.Aligned, "a fresh registration starts unaligned")

	s.handleHealthCheck(messages.MarshalHealthcheckWithPeriod(60))
	st, _ = relayStream(w)
	assert.True(t, st.Aligned, "the next aligned server frame reaches hbwatch")
}

// TestWatchAfterAlignedSwitchKeepsThePeriod covers a home session adopted
// after its connection switched to aligned: the registration must carry the
// confirmed period, so the wake check judges the connection before the next
// server frame.
func TestWatchAfterAlignedSwitchKeepsThePeriod(t *testing.T) {
	w := setTestWatcher(t)
	s := newAlignedTestSession(t, true, &recordConn{}, messages.ProtocolV1)

	s.handleHealthCheck(messages.MarshalHealthcheckWithPeriod(60))
	s.startWatch()

	st, registered := relayStream(w)
	require.True(t, registered, "the session registers at startWatch")
	assert.Equal(t, time.Minute, st.Period, "the registration carries the confirmed period")
}

// TestLateWatchAfterReadLoopExitDoesNotRegister covers adoptHome racing the
// read loop exit of the session it adopts: a registration after the exit
// must not stick, so the next session still registers its own connection.
func TestLateWatchAfterReadLoopExitDoesNotRegister(t *testing.T) {
	w := setTestWatcher(t)
	s := newAlignedTestSession(t, true, &recordConn{}, messages.ProtocolV1)

	// The read loop exits before the late registration.
	s.stopWatch()
	s.startWatch()
	assert.Empty(t, w.Snapshot().Streams, "an ended session must not be registered")

	next := newAlignedTestSession(t, true, &recordConn{}, messages.ProtocolV1)
	next.startWatch()
	assert.Len(t, w.Snapshot().Streams, 1, "the next session registers")
}

// TestStaleWatchKeepsNewerRegistration covers an old session that ends
// after a newer one registered: its unregister and its last frames must
// neither drop the newer registration nor mark it aligned.
func TestStaleWatchKeepsNewerRegistration(t *testing.T) {
	w := setTestWatcher(t)
	old := newAlignedTestSession(t, true, &recordConn{}, messages.ProtocolV1)
	old.startWatch()

	current := newAlignedTestSession(t, true, &recordConn{}, messages.ProtocolV1)
	current.startWatch()

	old.stopWatch()
	old.handleHealthCheck(messages.MarshalHealthcheckWithPeriod(60))

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
	s := newAlignedTestSession(t, true, clientEnd, messages.ProtocolV1)
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
	s := newAlignedTestSession(t, true, conn, messages.ProtocolV1)

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
