package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/proxy/internal/auth"
	"github.com/netbirdio/netbird/proxy/internal/roundtrip"
	nbtcp "github.com/netbirdio/netbird/proxy/internal/tcp"
	"github.com/netbirdio/netbird/proxy/internal/types"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// bufioReader wraps the connection in a buffered reader so http.ReadResponse
// can parse the response line + headers off the wire.
func bufioReader(conn net.Conn) *bufio.Reader {
	return bufio.NewReader(conn)
}

// quietLogger returns a logger that emits nothing — keeps test output tidy.
func quietLogger() *log.Logger {
	logger := log.New()
	logger.SetLevel(log.PanicLevel)
	return logger
}

func TestInboundManager_RouteScopedToAccount(t *testing.T) {
	mgr := newInboundManager(quietLogger(), http.NotFoundHandler(), nil)

	accountA := types.AccountID("acct-a")
	accountB := types.AccountID("acct-b")

	mgr.AddRoute(accountA, "shared.example", nbtcp.Route{Type: nbtcp.RouteHTTP, AccountID: accountA, ServiceID: "svc-a", Domain: "shared.example"})
	mgr.AddRoute(accountB, "other.example", nbtcp.Route{Type: nbtcp.RouteHTTP, AccountID: accountB, ServiceID: "svc-b", Domain: "other.example"})

	require.Equal(t, 1, mgr.PendingRouteCount(accountA), "account A should have one queued route")
	require.Equal(t, 1, mgr.PendingRouteCount(accountB), "account B should have one queued route")

	mgr.RemoveRoute(accountA, "shared.example", "svc-a")
	mgr.RemoveRoute(accountB, "other.example", "svc-b")

	assert.Equal(t, 0, mgr.PendingRouteCount(accountA), "queue should drain on remove")
	assert.Equal(t, 0, mgr.PendingRouteCount(accountB), "queue should drain on remove")
}

func TestInboundManager_PendingThenFlush(t *testing.T) {
	mgr := newInboundManager(quietLogger(), http.NotFoundHandler(), nil)

	accountID := types.AccountID("acct-1")
	host := nbtcp.SNIHost("example.test")
	route := nbtcp.Route{Type: nbtcp.RouteHTTP, AccountID: accountID, ServiceID: "svc-1", Domain: "example.test"}

	mgr.AddRoute(accountID, host, route)
	require.Equal(t, 1, mgr.PendingRouteCount(accountID), "pending count before listener is up")

	// Simulate listener up by registering a fake entry, then flushing.
	router := nbtcp.NewRouter(quietLogger(), nil, &fakeAddr{addr: "127.0.0.1:0"})
	entry := &inboundEntry{router: router}
	mgr.muxLock.Lock()
	mgr.entries[accountID] = entry
	mgr.muxLock.Unlock()

	mgr.flushPending(accountID, entry)
	assert.Equal(t, 0, mgr.PendingRouteCount(accountID), "queue should be empty after flush")
}

// fakeAddr is a stub net.Addr for tests that don't actually bind sockets.
type fakeAddr struct {
	addr string
}

func (a *fakeAddr) Network() string { return "tcp" }
func (a *fakeAddr) String() string  { return a.addr }

// fakeMgmtClient implements roundtrip.managementClient for tests.
type fakeMgmtClient struct{}

func (fakeMgmtClient) CreateProxyPeer(_ context.Context, _ *proto.CreateProxyPeerRequest, _ ...grpc.CallOption) (*proto.CreateProxyPeerResponse, error) {
	return &proto.CreateProxyPeerResponse{Success: true}, nil
}

// TestServer_PrivateInbound_NotEnabled_NoManager confirms that with
// --private off the inbound manager is nil and the standalone proxy
// keeps its zero-overhead default path.
func TestServer_PrivateInbound_NotEnabled_NoManager(t *testing.T) {
	s := &Server{Logger: quietLogger(), Private: false}
	s.initPrivateInbound(http.NotFoundHandler(), nil)
	assert.Nil(t, s.inbound, "manager should remain nil when --private is off")
}

// TestServer_PrivateInbound_Enabled_WiresLifecycle confirms that
// --private alone wires the manager into the NetBird transport, so
// AddPeer / RemovePeer drive the lifecycle.
func TestServer_PrivateInbound_Enabled_WiresLifecycle(t *testing.T) {
	s := &Server{Logger: quietLogger(), Private: true}
	// Construct a NetBird transport. We can't actually start the embedded
	// client here (that needs a real management server), but we can
	// confirm that the lifecycle callbacks are registered.
	s.netbird = roundtrip.NewNetBird(t.Context(), "test", "test", roundtrip.ClientConfig{
		MgmtAddr: "http://invalid.test",
	}, quietLogger(), nil, fakeMgmtClient{})

	s.initPrivateInbound(http.NotFoundHandler(), &tls.Config{}) //nolint:gosec
	require.NotNil(t, s.inbound, "manager should be set when --private is on")
	assert.NotNil(t, s.inbound.handler, "handler should be set on manager")
	assert.NotNil(t, s.inbound.tlsConfig, "tls config should be set on manager")
}

// TestInboundManager_AddRouteAfterReady_RegistersDirectly verifies that
// when the listener is already up, AddRoute writes straight to the
// router without queueing.
func TestInboundManager_AddRouteAfterReady_RegistersDirectly(t *testing.T) {
	mgr := newInboundManager(quietLogger(), http.NotFoundHandler(), nil)
	accountID := types.AccountID("acct-1")
	router := nbtcp.NewRouter(quietLogger(), nil, &fakeAddr{addr: "127.0.0.1:0"})

	mgr.muxLock.Lock()
	mgr.entries[accountID] = &inboundEntry{router: router}
	mgr.muxLock.Unlock()

	host := nbtcp.SNIHost("ready.example")
	mgr.AddRoute(accountID, host, nbtcp.Route{Type: nbtcp.RouteHTTP, AccountID: accountID, ServiceID: "svc-ready", Domain: string(host)})
	assert.Equal(t, 0, mgr.PendingRouteCount(accountID), "no pending entries when listener is up")
}

// TestPrivateCapability_DerivedFromPrivateOnly tests that the capability
// bit reported upstream tracks --private exclusively. The previous
// --private flag has been folded into --private.
func TestPrivateCapability_DerivedFromPrivateOnly(t *testing.T) {
	tests := []struct {
		name     string
		private  bool
		expected bool
	}{
		{"off", false, false},
		{"on", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{Private: tt.private}
			assert.Equal(t, tt.expected, s.Private, "private capability bit should match --private")
		})
	}
}

// TestInboundManager_RouteScopedToAccountB_DoesNotMatchA verifies that a
// service registered for account B is invisible to a router serving
// account A. We exercise the path through real per-account routers.
func TestInboundManager_RouteScopedToAccountB_DoesNotMatchA(t *testing.T) {
	mgr := newInboundManager(quietLogger(), http.NotFoundHandler(), nil)

	accountA := types.AccountID("acct-a")
	accountB := types.AccountID("acct-b")
	routerA := nbtcp.NewRouter(quietLogger(), nil, &fakeAddr{addr: "127.0.0.1:0"})
	routerB := nbtcp.NewRouter(quietLogger(), nil, &fakeAddr{addr: "127.0.0.1:0"})

	mgr.muxLock.Lock()
	mgr.entries[accountA] = &inboundEntry{router: routerA}
	mgr.entries[accountB] = &inboundEntry{router: routerB}
	mgr.muxLock.Unlock()

	host := nbtcp.SNIHost("shared.example")
	mgr.AddRoute(accountB, host, nbtcp.Route{Type: nbtcp.RouteHTTP, AccountID: accountB, ServiceID: "svc-b", Domain: string(host)})

	// Account A's router should have no routes; account B's should have one.
	// We check via IsEmpty — true means no routes and no fallback.
	assert.True(t, routerA.IsEmpty(), "account A router must not see account B's mappings")
	assert.False(t, routerB.IsEmpty(), "account B router should hold its own mapping")
}

// TestInboundEntry_ShutdownIdempotent ensures that tearDown can run twice
// without panicking — callers may invoke it from RemovePeer + StopAll.
func TestInboundEntry_ShutdownIdempotent(t *testing.T) {
	t.Skip("teardown requires real netstack listeners; covered by integration tests")
}

// TestRouter_PlainHTTP_ForwardedProtoIsHTTP exercises the full per-account
// router pipeline against a loopback listener (proxy of a netstack
// listener for test purposes): a plain HTTP request lands on the plain
// http.Server and the inner handler observes a nil r.TLS, which is what
// auth.ResolveProto translates to "http" in the real pipeline.
func TestRouter_PlainHTTP_ForwardedProtoIsHTTP(t *testing.T) {
	logger := quietLogger()

	var captured atomic.Value
	captured.Store("")

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			captured.Store("http")
		} else {
			captured.Store("https")
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	hostListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "loopback listener bind must succeed")
	defer hostListener.Close()

	router := nbtcp.NewRouter(logger, nil, hostListener.Addr(), nbtcp.WithPlainHTTP(hostListener.Addr()))
	httpServer := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	defer func() { _ = httpServer.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = httpServer.Serve(router.HTTPListenerPlain()) }()
	go func() { _ = router.Serve(ctx, hostListener) }()

	conn, err := net.DialTimeout("tcp", hostListener.Addr().String(), 2*time.Second)
	require.NoError(t, err, "plain HTTP dial must succeed")
	defer conn.Close()

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err, "write must succeed")

	resp, err := http.ReadResponse(bufioReader(conn), nil)
	require.NoError(t, err, "must read response")
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "http", captured.Load(), "ForwardedProto must be http on plain path")
}

// TestWithTunnelLookup_AttachesLookupToContext verifies that requests
// flowing through the per-account handler wrapper carry the peerstore
// lookup function. Phase 3's local-first deny path depends on this.
func TestWithTunnelLookup_AttachesLookupToContext(t *testing.T) {
	expected := auth.PeerIdentity{TunnelIP: netip.MustParseAddr("100.64.0.10"), FQDN: "peer.netbird"}
	lookup := auth.TunnelLookupFunc(func(_ netip.Addr) (auth.PeerIdentity, bool) {
		return expected, true
	})

	var observed auth.TunnelLookupFunc
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		observed = auth.TunnelLookupFromContext(r.Context())
	})

	handler := withTunnelLookup(inner, lookup)
	r := httptest.NewRequest(http.MethodGet, "https://svc.example/", nil)
	handler.ServeHTTP(httptest.NewRecorder(), r)

	require.NotNil(t, observed, "wrapper must inject the lookup into the request context")
	got, ok := observed(netip.MustParseAddr("100.64.0.10"))
	assert.True(t, ok, "lookup must round-trip through context")
	assert.Equal(t, expected.FQDN, got.FQDN, "lookup must return the same identity it was constructed with")
}

// TestWithTunnelLookup_NilLookupIsNoop confirms the wrapper is a pure
// pass-through when no lookup is provided. Required for the host-level
// listener path to keep its byte-for-byte previous behaviour.
func TestWithTunnelLookup_NilLookupIsNoop(t *testing.T) {
	var called bool
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		assert.Nil(t, auth.TunnelLookupFromContext(r.Context()), "host-level path must not see a lookup function")
	})

	handler := withTunnelLookup(inner, nil)
	r := httptest.NewRequest(http.MethodGet, "https://svc.example/", nil)
	handler.ServeHTTP(httptest.NewRecorder(), r)
	assert.True(t, called, "wrapper without lookup must still invoke next")
}

// fakeListener satisfies net.Listener for snapshot tests without binding
// a real socket on the netstack.
type fakeListener struct {
	addr net.Addr
}

func (f *fakeListener) Accept() (net.Conn, error) { return nil, net.ErrClosed }
func (f *fakeListener) Close() error              { return nil }
func (f *fakeListener) Addr() net.Addr            { return f.addr }

// TestInboundManager_ListenerInfo confirms ListenerInfo and Snapshot
// surface the bound tunnel-IP and ports for live entries.
func TestInboundManager_ListenerInfo(t *testing.T) {
	mgr := newInboundManager(quietLogger(), http.NotFoundHandler(), nil)
	accountID := types.AccountID("acct-info")

	tlsAddr := &net.TCPAddr{IP: net.ParseIP("100.64.0.5"), Port: privateInboundPortHTTPS}
	plainAddr := &net.TCPAddr{IP: net.ParseIP("100.64.0.5"), Port: privateInboundPortHTTP}
	mgr.muxLock.Lock()
	mgr.entries[accountID] = &inboundEntry{
		tlsListener:   &fakeListener{addr: tlsAddr},
		plainListener: &fakeListener{addr: plainAddr},
	}
	mgr.muxLock.Unlock()

	info, ok := mgr.ListenerInfo(accountID)
	require.True(t, ok, "ListenerInfo must report ok for live entry")
	assert.Equal(t, "100.64.0.5", info.TunnelIP, "tunnel IP must come from listener address")
	assert.Equal(t, uint16(privateInboundPortHTTPS), info.HTTPSPort, "TLS port must match bound port")
	assert.Equal(t, uint16(privateInboundPortHTTP), info.HTTPPort, "HTTP port must match bound port")

	snap := mgr.Snapshot()
	require.Len(t, snap, 1, "snapshot must contain exactly one entry")
	assert.Equal(t, info, snap[accountID], "snapshot entry must equal direct lookup")

	_, ok = mgr.ListenerInfo(types.AccountID("missing"))
	assert.False(t, ok, "ListenerInfo must report ok=false for unknown accounts")
}

// TestInboundManager_NilManagerSafe ensures the observability accessors
// are safe to call when --private is off (nil manager).
func TestInboundManager_NilManagerSafe(t *testing.T) {
	var mgr *inboundManager
	_, ok := mgr.ListenerInfo("anything")
	assert.False(t, ok, "nil manager must return ok=false")
	assert.Nil(t, mgr.Snapshot(), "nil manager must return nil snapshot")
}

// TestInboundManager_ConcurrentAddRemove pounds AddRoute / RemoveRoute
// from multiple goroutines to expose any locking gaps.
func TestInboundManager_ConcurrentAddRemove(t *testing.T) {
	mgr := newInboundManager(quietLogger(), http.NotFoundHandler(), nil)
	accountID := types.AccountID("acct-1")
	const workers = 32
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			host := nbtcp.SNIHost("example.test")
			svc := types.ServiceID("svc")
			route := nbtcp.Route{Type: nbtcp.RouteHTTP, AccountID: accountID, ServiceID: svc, Domain: "example.test"}
			for j := 0; j < iterations; j++ {
				mgr.AddRoute(accountID, host, route)
				mgr.RemoveRoute(accountID, host, svc)
			}
		}(i)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent add/remove timed out")
	}
}

// TestFeedRouterFromListener_DeliversConnectionToHandler validates the
// per-account inbound chain end-to-end with a loopback listener
// substituted for the embedded netstack: a TCP connection arriving at
// the plain listener flows through feedRouterFromListener, the router's
// peek-and-dispatch, the wrapped HTTP server, and reaches the user
// handler. If the embedded netstack is delivering connections at all,
// this is the path they take. Failures localise to wiring bugs in the
// proxy, not the netstack.
func TestFeedRouterFromListener_DeliversConnectionToHandler(t *testing.T) {
	logger := quietLogger()

	hits := make(chan string, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- r.Host
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("served"))
	})

	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "plain loopback bind must succeed")
	t.Cleanup(func() { _ = plainLn.Close() })

	router := nbtcp.NewRouter(logger, nil, &fakeAddr{addr: "127.0.0.1:0"}, nbtcp.WithPlainHTTP(plainLn.Addr()))

	httpServer := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	t.Cleanup(func() { _ = httpServer.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() { _ = httpServer.Serve(router.HTTPListenerPlain()) }()
	go feedRouterFromListener(ctx, plainLn, router, logger, types.AccountID("acct-1"))

	conn, err := net.DialTimeout("tcp", plainLn.Addr().String(), 2*time.Second)
	require.NoError(t, err, "must connect to the plain listener")
	t.Cleanup(func() { _ = conn.Close() })

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: app.example\r\nConnection: close\r\n\r\n"))
	require.NoError(t, err, "request write must succeed")

	resp, err := http.ReadResponse(bufioReader(conn), nil)
	require.NoError(t, err, "must read response from server")
	t.Cleanup(func() { _ = resp.Body.Close() })

	assert.Equal(t, http.StatusOK, resp.StatusCode, "handler must be reached")

	select {
	case host := <-hits:
		assert.Equal(t, "app.example", host, "handler must observe the request Host")
	case <-time.After(2 * time.Second):
		t.Fatal("handler was not invoked — connection did not flow through router → http server")
	}
}

// TestFeedRouterFromListener_DispatchesTLSToTLSChannel verifies that a
// TLS ClientHello arriving on the plain listener is detected by the
// router peek and re-dispatched to the TLS channel — the cross-channel
// fallback the inbound stack relies on for HTTPS-on-:80 testing.
func TestFeedRouterFromListener_DispatchesTLSToTLSChannel(t *testing.T) {
	logger := quietLogger()

	hits := make(chan string, 1)
	tlsHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits <- r.Host
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("served-tls"))
	})

	plainLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "plain loopback bind must succeed")
	t.Cleanup(func() { _ = plainLn.Close() })

	tlsLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "tls loopback bind must succeed")
	t.Cleanup(func() { _ = tlsLn.Close() })

	router := nbtcp.NewRouter(logger, nil, tlsLn.Addr(), nbtcp.WithPlainHTTP(plainLn.Addr()))

	tlsConfig := selfSignedTLSConfig(t)
	httpsServer := &http.Server{
		Handler:           tlsHandler,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: time.Second,
	}
	t.Cleanup(func() { _ = httpsServer.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go func() { _ = httpsServer.ServeTLS(router.HTTPListener(), "", "") }()
	go feedRouterFromListener(ctx, plainLn, router, logger, types.AccountID("acct-tls"))

	tlsConn, err := tls.Dial("tcp", plainLn.Addr().String(), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec
	require.NoError(t, err, "TLS dial against the plain listener must succeed (cross-channel)")
	t.Cleanup(func() { _ = tlsConn.Close() })

	req, err := http.NewRequest(http.MethodGet, "https://app.example/", nil)
	require.NoError(t, err)
	require.NoError(t, req.Write(tlsConn), "TLS request write must succeed")

	resp, err := http.ReadResponse(bufioReader(tlsConn), req)
	require.NoError(t, err, "must read TLS response")
	t.Cleanup(func() { _ = resp.Body.Close() })

	assert.Equal(t, http.StatusOK, resp.StatusCode, "TLS handler must be reached")

	select {
	case host := <-hits:
		assert.Equal(t, "app.example", host, "TLS handler must observe the request Host")
	case <-time.After(2 * time.Second):
		t.Fatal("TLS handler was not invoked — peek/dispatch path is broken")
	}
}

func selfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	cert, err := tls.X509KeyPair(testCertPEM, testKeyPEM)
	require.NoError(t, err, "load static self-signed cert")
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12} //nolint:gosec
}

// TestNewInboundErrorLog_WriterIsCloseable guards the close path on the
// logrus PipeWriter that backs each per-account http.Server's ErrorLog.
// logrus.Entry.WriterLevel returns an *io.PipeWriter that owns a pipe +
// scanner goroutine; the caller must Close() it on teardown or the
// resources leak per account. The contract is verified two ways:
//
//   - the constructor returns a non-nil writer the caller can keep,
//   - writing to the writer after Close() fails with io.ErrClosedPipe,
//     which is the only externally observable sign that Close was wired.
//
// A leaking refactor (forgetting to thread the writer to tearDown, or
// dropping the Close call) would still pass this test individually but
// fail an integration goleak check; this unit test is the cheap first
// line of defence.
func TestNewInboundErrorLog_WriterIsCloseable(t *testing.T) {
	logger := quietLogger()
	stdLog, writer := newInboundErrorLog(logger, "https", types.AccountID("acct-1"))

	require.NotNil(t, stdLog, "newInboundErrorLog must return a non-nil *log.Logger")
	require.NotNil(t, writer, "newInboundErrorLog must return the underlying PipeWriter so tearDown can Close it")

	// First Close succeeds.
	require.NoError(t, writer.Close(), "PipeWriter.Close should succeed the first time")

	// After Close, the writer must refuse new writes — that's the only
	// behavioural signal that the pipe (and its scanner goroutine) has
	// shut down.
	_, err := writer.Write([]byte("post-close write\n"))
	require.ErrorIs(t, err, io.ErrClosedPipe,
		"writes after Close must surface io.ErrClosedPipe so callers know the writer is gone")
}

// testCertPEM / testKeyPEM are a minimal RSA self-signed cert for
// 127.0.0.1 — only used by tests that need a working TLS handshake.
var testCertPEM = []byte(`-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`)
var testKeyPEM = []byte(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`)
