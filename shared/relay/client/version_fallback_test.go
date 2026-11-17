package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/relay/server"
	"github.com/netbirdio/netbird/relay/server/listener"
	"github.com/netbirdio/netbird/relay/server/listener/quic"
	"github.com/netbirdio/netbird/relay/server/listener/ws"
	netErr "github.com/netbirdio/netbird/shared/relay/client/dialer/net"
	"github.com/netbirdio/netbird/shared/relay/messages"
	quictls "github.com/netbirdio/netbird/shared/relay/tls"
)

// oldRelay behaves like a relay server before v0.82.0: it closes the
// connection without an answer when the first frame is not v1. A v1 auth is
// handed to a current relay, which answers v1 because the client advertised v1.
// Once upgraded is set, every connection goes to the current relay unchanged.
type oldRelay struct {
	addr      string
	rejected  atomic.Int32
	rejectAll bool
	upgraded  atomic.Bool

	mu    sync.Mutex
	conns []listener.Conn
}

// start serves the old relay on WebSocket and QUIC at r.addr until the test ends.
func (r *oldRelay) start(t *testing.T) {
	t.Helper()
	srv, err := server.NewServer(newClientTestServerConfig(r.addr))
	require.NoError(t, err)
	accept := srv.RelayAccept()

	quicTLS, err := quictls.ServerQUICTLSConfig(nil)
	require.NoError(t, err)
	wsListener := &ws.Listener{Address: r.addr}
	quicListener := &quic.Listener{Address: r.addr, TLSConfig: quicTLS}
	require.NoError(t, wsListener.Bind())
	require.NoError(t, quicListener.Bind())

	var wg sync.WaitGroup
	for _, l := range []interface {
		Serve(func(listener.Conn)) error
	}{wsListener, quicListener} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = l.Serve(func(conn listener.Conn) { r.accept(conn, accept) })
		}()
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = wsListener.Shutdown(ctx)
		_ = quicListener.Shutdown(ctx)
		wg.Wait()
	})
}

func (r *oldRelay) accept(conn listener.Conn, next func(listener.Conn)) {
	if r.upgraded.Load() {
		r.track(conn)
		next(conn)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	buf := make([]byte, messages.MaxHandshakeSize)
	n, err := conn.Read(ctx, buf)
	if err != nil || r.rejectAll || buf[0] != byte(messages.ProtocolV1) {
		if err == nil && buf[0] != byte(messages.ProtocolV1) {
			r.rejected.Add(1)
		}
		_ = conn.Close()
		return
	}
	r.track(conn)
	next(&replayConn{Conn: conn, first: buf[:n]})
}

func (r *oldRelay) track(conn listener.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.conns = append(r.conns, conn)
}

// dropAll closes every accepted connection from the server side, like a relay
// instance that goes away.
func (r *oldRelay) dropAll() {
	r.mu.Lock()
	conns := r.conns
	r.conns = nil
	r.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// replayConn returns the already read first frame before reading on.
type replayConn struct {
	listener.Conn
	first []byte
}

func (c *replayConn) Read(ctx context.Context, b []byte) (int, error) {
	if c.first != nil {
		n := copy(b, c.first)
		c.first = nil
		return n, nil
	}
	return c.Conn.Read(ctx, b)
}

func connectAligned(t *testing.T, url string, vf *versionFallback, peerID string) *Client {
	t.Helper()
	c := NewClient(url, tokenStore(t), peerID, iface.DefaultMTU)
	c.alignedRequest = askAligned(60 * time.Second)
	c.SetVersionFallback(vf)
	require.NoError(t, c.Connect(context.Background()))
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func assertRelayedTraffic(t *testing.T, alice, bob *Client) {
	t.Helper()
	ctx := context.Background()
	aliceToBob, err := alice.OpenConn(ctx, "bob")
	require.NoError(t, err)
	bobToAlice, err := bob.OpenConn(ctx, "alice")
	require.NoError(t, err)

	buf := make([]byte, 1500)
	_, err = aliceToBob.Write([]byte("from alice"))
	require.NoError(t, err)
	n, err := bobToAlice.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "from alice", string(buf[:n]), "bob must receive alice's message")

	_, err = bobToAlice.Write([]byte("from bob"))
	require.NoError(t, err)
	n, err = aliceToBob.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "from bob", string(buf[:n]), "alice must receive bob's message")
}

func runOldRelayFallback(t *testing.T, addr string) *Client {
	t.Helper()
	relay := &oldRelay{addr: addr}
	relay.start(t)
	url := "rel://" + addr
	vf := newVersionFallback()

	alice := connectAligned(t, url, vf, "alice")
	assert.Equal(t, int32(1), relay.rejected.Load(), "the old relay must see exactly one v2 auth")
	assert.Equal(t, messages.ProtocolV1, alice.enc.Version(), "the client must fall back to v1")
	assert.Zero(t, alice.alignedPeriod, "v1 runs without the aligned heartbeat")
	assert.Equal(t, messages.ProtocolV1, vf.maxVersion(url), "the relay must be remembered as v1 only")

	bob := connectAligned(t, url, vf, "bob")
	assert.Equal(t, int32(1), relay.rejected.Load(), "a remembered relay must not get a v2 auth again")
	assertRelayedTraffic(t, alice, bob)

	// A reconnect of the same client goes straight to v1 as well.
	require.NoError(t, alice.Close())
	require.NoError(t, alice.Connect(context.Background()))
	assert.Equal(t, int32(1), relay.rejected.Load(), "a reconnect must not retry v2")
	assert.Equal(t, messages.ProtocolV1, alice.enc.Version(), "the reconnect must stay on v1")
	return alice
}

func TestOldRelayFallbackToV1(t *testing.T) {
	t.Setenv(EnvRelayTransport, string(TransportModeWS))
	alice := runOldRelayFallback(t, "127.0.0.1:50921")
	assert.Equal(t, "ws", alice.Transport(), "transport")
}

func TestOldRelayFallbackV1AlsoFails(t *testing.T) {
	t.Setenv(EnvRelayTransport, string(TransportModeWS))
	addr := "127.0.0.1:50922"
	relay := &oldRelay{addr: addr, rejectAll: true}
	relay.start(t)
	url := "rel://" + addr
	vf := newVersionFallback()

	c := NewClient(url, tokenStore(t), "alice", iface.DefaultMTU)
	c.alignedRequest = askAligned(60 * time.Second)
	c.SetVersionFallback(vf)
	err := c.Connect(context.Background())
	require.Error(t, err)
	assert.NotErrorIs(t, err, errV2AuthRejected, "a failed v1 retry must not report the v2 reject")
	assert.Equal(t, messages.CurrentProtocolVersion, vf.maxVersion(url), "a relay that rejects v1 too must not be pinned to v1")
}

func TestNewRelayKeepsV2(t *testing.T) {
	addr := "127.0.0.1:50923"
	srv, err := server.NewServer(newClientTestServerConfig(addr))
	require.NoError(t, err)
	errChan := make(chan error, 1)
	go func() {
		if err := srv.Listen(server.ListenerConfig{Address: addr}); err != nil {
			errChan <- err
		}
	}()
	t.Cleanup(func() { _ = srv.Shutdown(context.Background()) })
	require.NoError(t, waitForServerToStart(errChan))

	url := "rel://" + addr
	vf := newVersionFallback()
	alice := connectAligned(t, url, vf, "alice")
	assert.Equal(t, messages.ProtocolV2, alice.enc.Version(), "a new relay must select v2")
	assert.Equal(t, 60*time.Second, alice.alignedPeriod, "v2 keeps the aligned period")
	assert.Equal(t, messages.CurrentProtocolVersion, vf.maxVersion(url), "a new relay must not be pinned to v1")
}

func TestAuthRejectErr(t *testing.T) {
	live := context.Background()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	tests := []struct {
		name       string
		ctx        context.Context
		advertised messages.ProtocolVersion
		err        error
		rejected   bool
	}{
		{"websocket eof", live, messages.ProtocolV2, fmt.Errorf("failed to get reader: %w", io.EOF), true},
		{"quic close code 0", live, messages.ProtocolV2, netErr.ErrClosedByServer, true},
		{"websocket close frame", live, messages.ProtocolV2, websocket.CloseError{Code: websocket.StatusPolicyViolation}, true},
		{"v1 auth", live, messages.ProtocolV1, io.EOF, false},
		{"cancelled dial", cancelled, messages.ProtocolV2, io.EOF, false},
		{"timeout", live, messages.ProtocolV2, errors.New("read operation timed out"), false},
		{"reset", live, messages.ProtocolV2, syscall.ECONNRESET, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := authRejectErr(tt.ctx, tt.advertised, tt.err)
			assert.Equal(t, tt.rejected, errors.Is(err, errV2AuthRejected), "rejected")
			assert.ErrorIs(t, err, tt.err, "the read error must stay in the chain")
		})
	}
}

func TestVersionFallbackNil(t *testing.T) {
	var vf *versionFallback
	vf.recordV1Only("rel://a")
	vf.v1Dropped("rel://a")
	vf.recordV2("rel://a")
	assert.Equal(t, messages.CurrentProtocolVersion, vf.maxVersion("rel://a"), "a nil tracker remembers nothing")
}
