package tcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/proxy/internal/restrict"
	"github.com/netbirdio/netbird/proxy/internal/types"
)

func TestRouter_HTTPRouting(t *testing.T) {
	logger := log.StandardLogger()
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}

	router := NewRouter(logger, nil, addr)
	router.AddRoute("example.com", Route{Type: RouteHTTP})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = router.Serve(ctx, ln)
	}()

	// Dial in a goroutine. The TLS handshake will block since nothing
	// completes it on the HTTP side, but we only care about routing.
	go func() {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			return
		}
		// Send a TLS ClientHello manually.
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         "example.com",
			InsecureSkipVerify: true, //nolint:gosec
		})
		_ = tlsConn.Handshake()
		tlsConn.Close()
	}()

	// Verify the connection was routed to the HTTP channel.
	select {
	case conn := <-router.httpCh:
		assert.NotNil(t, conn)
		conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("no connection received on HTTP channel")
	}
}

func TestRouter_TCPRouting(t *testing.T) {
	logger := log.StandardLogger()
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}

	// Set up a TLS backend that the relay will connect to.
	backendCert := generateSelfSignedCert(t)
	backendLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{backendCert},
	})
	require.NoError(t, err)
	defer backendLn.Close()

	backendAddr := backendLn.Addr().String()

	// Accept one connection on the backend, echo data back.
	backendReady := make(chan struct{})
	go func() {
		close(backendReady)
		conn, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(buf[:n])
	}()
	<-backendReady

	dialResolve := func(accountID types.AccountID) (types.DialContextFunc, error) {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, address)
		}, nil
	}

	router := NewRouter(logger, dialResolve, addr)
	router.AddRoute("tcp.example.com", Route{
		Type:      RouteTCP,
		AccountID: "test-account",
		ServiceID: "test-service",
		Target:    backendAddr,
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = router.Serve(ctx, ln)
	}()

	// Connect as a TLS client; the proxy should passthrough to the backend.
	clientConn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName:         "tcp.example.com",
		InsecureSkipVerify: true, //nolint:gosec
	})
	require.NoError(t, err)
	defer clientConn.Close()

	testData := []byte("hello through TCP passthrough")
	_, err = clientConn.Write(testData)
	require.NoError(t, err)

	buf := make([]byte, 1024)
	n, err := clientConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, testData, buf[:n], "should receive echoed data through TCP passthrough")
}

func TestRouter_UnknownSNIGoesToHTTP(t *testing.T) {
	logger := log.StandardLogger()
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}

	router := NewRouter(logger, nil, addr)
	// No routes registered.

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = router.Serve(ctx, ln)
	}()

	go func() {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			return
		}
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         "unknown.example.com",
			InsecureSkipVerify: true, //nolint:gosec
		})
		_ = tlsConn.Handshake()
		tlsConn.Close()
	}()

	select {
	case conn := <-router.httpCh:
		assert.NotNil(t, conn)
		conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("unknown SNI should be routed to HTTP")
	}
}

// TestRouter_NonTLSConnectionDropped verifies that a non-TLS connection
// on the shared port is closed by the router (SNI peek fails to find a
// valid ClientHello, so there is no route match).
func TestRouter_NonTLSConnectionDropped(t *testing.T) {
	logger := log.StandardLogger()
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}

	// Register a TLS passthrough route. Non-TLS should NOT match.
	dialResolve := func(accountID types.AccountID) (types.DialContextFunc, error) {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, address)
		}, nil
	}

	router := NewRouter(logger, dialResolve, addr)
	router.AddRoute("tcp.example.com", Route{
		Type:      RouteTCP,
		AccountID: "test-account",
		ServiceID: "test-service",
		Target:    "127.0.0.1:9999",
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = router.Serve(ctx, ln)
	}()

	// Send plain HTTP (non-TLS) data.
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, _ = conn.Write([]byte("GET / HTTP/1.1\r\nHost: tcp.example.com\r\n\r\n"))

	// Non-TLS traffic on a port with RouteTCP goes to the HTTP channel
	// because there's no valid SNI to match. Verify it reaches HTTP.
	select {
	case httpConn := <-router.httpCh:
		assert.NotNil(t, httpConn, "non-TLS connection should fall through to HTTP")
		httpConn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("non-TLS connection was not routed to HTTP")
	}
}

// TestRouter_TLSAndHTTPCoexist verifies that a shared port with both HTTP
// and TLS passthrough routes correctly demuxes based on the SNI hostname.
func TestRouter_TLSAndHTTPCoexist(t *testing.T) {
	logger := log.StandardLogger()
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}

	backendCert := generateSelfSignedCert(t)
	backendLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{backendCert},
	})
	require.NoError(t, err)
	defer backendLn.Close()

	// Backend echoes data.
	go func() {
		conn, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(buf[:n])
	}()

	dialResolve := func(accountID types.AccountID) (types.DialContextFunc, error) {
		return func(ctx context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, address)
		}, nil
	}

	router := NewRouter(logger, dialResolve, addr)
	// HTTP route.
	router.AddRoute("app.example.com", Route{Type: RouteHTTP})
	// TLS passthrough route.
	router.AddRoute("tcp.example.com", Route{
		Type:      RouteTCP,
		AccountID: "test-account",
		ServiceID: "test-service",
		Target:    backendLn.Addr().String(),
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = router.Serve(ctx, ln)
	}()

	// 1. TLS connection with SNI "tcp.example.com" → TLS passthrough.
	tlsConn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName:         "tcp.example.com",
		InsecureSkipVerify: true, //nolint:gosec
	})
	require.NoError(t, err)

	testData := []byte("passthrough data")
	_, err = tlsConn.Write(testData)
	require.NoError(t, err)
	buf := make([]byte, 1024)
	n, err := tlsConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, testData, buf[:n], "TLS passthrough should relay data")
	tlsConn.Close()

	// 2. TLS connection with SNI "app.example.com" → HTTP handler.
	go func() {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			return
		}
		c := tls.Client(conn, &tls.Config{
			ServerName:         "app.example.com",
			InsecureSkipVerify: true, //nolint:gosec
		})
		_ = c.Handshake()
		c.Close()
	}()

	select {
	case httpConn := <-router.httpCh:
		assert.NotNil(t, httpConn, "HTTP SNI should go to HTTP handler")
		httpConn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP-route connection was not delivered to HTTP handler")
	}
}

func TestRouter_AddRemoveRoute(t *testing.T) {
	logger := log.StandardLogger()
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	router := NewRouter(logger, nil, addr)

	router.AddRoute("a.example.com", Route{Type: RouteHTTP, ServiceID: "svc-a"})
	router.AddRoute("b.example.com", Route{Type: RouteTCP, ServiceID: "svc-b", Target: "10.0.0.1:5432"})

	route, ok := router.lookupRoute("a.example.com")
	assert.True(t, ok)
	assert.Equal(t, RouteHTTP, route.Type)

	route, ok = router.lookupRoute("b.example.com")
	assert.True(t, ok)
	assert.Equal(t, RouteTCP, route.Type)

	router.RemoveRoute("a.example.com", "svc-a")
	_, ok = router.lookupRoute("a.example.com")
	assert.False(t, ok)
}

func TestChanListener_AcceptAndClose(t *testing.T) {
	ch := make(chan net.Conn, 1)
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	ln := newChanListener(ch, addr)

	assert.Equal(t, addr, ln.Addr())

	// Send a connection.
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	ch <- serverConn

	conn, err := ln.Accept()
	require.NoError(t, err)
	assert.Equal(t, serverConn, conn)

	// Close should cause Accept to return error.
	require.NoError(t, ln.Close())
	// Double close should be safe.
	require.NoError(t, ln.Close())

	_, err = ln.Accept()
	assert.ErrorIs(t, err, net.ErrClosed)
}

func TestRouter_HTTPPrecedenceGuard(t *testing.T) {
	logger := log.StandardLogger()
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	router := NewRouter(logger, nil, addr)

	host := SNIHost("app.example.com")

	t.Run("http takes precedence over tcp at lookup", func(t *testing.T) {
		router.AddRoute(host, Route{Type: RouteHTTP, ServiceID: "svc-http"})
		router.AddRoute(host, Route{Type: RouteTCP, ServiceID: "svc-tcp", Target: "10.0.0.1:443"})

		route, ok := router.lookupRoute(host)
		require.True(t, ok)
		assert.Equal(t, RouteHTTP, route.Type, "HTTP route must take precedence over TCP")
		assert.Equal(t, types.ServiceID("svc-http"), route.ServiceID)

		router.RemoveRoute(host, "svc-http")
		router.RemoveRoute(host, "svc-tcp")
	})

	t.Run("tcp becomes active when http is removed", func(t *testing.T) {
		router.AddRoute(host, Route{Type: RouteHTTP, ServiceID: "svc-http"})
		router.AddRoute(host, Route{Type: RouteTCP, ServiceID: "svc-tcp", Target: "10.0.0.1:443"})

		router.RemoveRoute(host, "svc-http")

		route, ok := router.lookupRoute(host)
		require.True(t, ok)
		assert.Equal(t, RouteTCP, route.Type, "TCP should take over after HTTP removal")
		assert.Equal(t, types.ServiceID("svc-tcp"), route.ServiceID)

		router.RemoveRoute(host, "svc-tcp")
	})

	t.Run("order of add does not matter", func(t *testing.T) {
		router.AddRoute(host, Route{Type: RouteTCP, ServiceID: "svc-tcp", Target: "10.0.0.1:443"})
		router.AddRoute(host, Route{Type: RouteHTTP, ServiceID: "svc-http"})

		route, ok := router.lookupRoute(host)
		require.True(t, ok)
		assert.Equal(t, RouteHTTP, route.Type, "HTTP takes precedence regardless of add order")

		router.RemoveRoute(host, "svc-http")
		router.RemoveRoute(host, "svc-tcp")
	})

	t.Run("same service id updates in place", func(t *testing.T) {
		router.AddRoute(host, Route{Type: RouteTCP, ServiceID: "svc-1", Target: "10.0.0.1:443"})
		router.AddRoute(host, Route{Type: RouteTCP, ServiceID: "svc-1", Target: "10.0.0.2:443"})

		route, ok := router.lookupRoute(host)
		require.True(t, ok)
		assert.Equal(t, "10.0.0.2:443", route.Target, "route should be updated in place")

		router.RemoveRoute(host, "svc-1")
		_, ok = router.lookupRoute(host)
		assert.False(t, ok)
	})

	t.Run("double remove is safe", func(t *testing.T) {
		router.AddRoute(host, Route{Type: RouteHTTP, ServiceID: "svc-1"})
		router.RemoveRoute(host, "svc-1")
		router.RemoveRoute(host, "svc-1")

		_, ok := router.lookupRoute(host)
		assert.False(t, ok, "route should be gone after removal")
	})

	t.Run("remove does not affect other hosts", func(t *testing.T) {
		router.AddRoute("a.example.com", Route{Type: RouteHTTP, ServiceID: "svc-a"})
		router.AddRoute("b.example.com", Route{Type: RouteTCP, ServiceID: "svc-b", Target: "10.0.0.2:22"})

		router.RemoveRoute("a.example.com", "svc-a")

		_, ok := router.lookupRoute(SNIHost("a.example.com"))
		assert.False(t, ok)

		route, ok := router.lookupRoute(SNIHost("b.example.com"))
		require.True(t, ok)
		assert.Equal(t, RouteTCP, route.Type, "removing one host must not affect another")

		router.RemoveRoute("b.example.com", "svc-b")
	})
}

func TestRouter_SetRemoveFallback(t *testing.T) {
	logger := log.StandardLogger()
	router := NewPortRouter(logger, nil)

	assert.True(t, router.IsEmpty(), "new port router should be empty")

	router.SetFallback(Route{Type: RouteTCP, ServiceID: "svc-fb", Target: "10.0.0.1:5432"})
	assert.False(t, router.IsEmpty(), "router with fallback should not be empty")

	router.AddRoute("a.example.com", Route{Type: RouteTCP, ServiceID: "svc-a", Target: "10.0.0.2:443"})
	assert.False(t, router.IsEmpty())

	router.RemoveFallback("svc-fb")
	assert.False(t, router.IsEmpty(), "router with SNI route should not be empty")

	router.RemoveRoute("a.example.com", "svc-a")
	assert.True(t, router.IsEmpty(), "router with no routes and no fallback should be empty")
}

func TestPortRouter_FallbackRelaysData(t *testing.T) {
	// Backend echo server.
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer backendLn.Close()

	go func() {
		conn, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(buf[:n])
	}()

	dialResolve := func(_ types.AccountID) (types.DialContextFunc, error) {
		return func(_ context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, address)
		}, nil
	}

	logger := log.StandardLogger()
	router := NewPortRouter(logger, dialResolve)
	router.SetFallback(Route{
		Type:      RouteTCP,
		AccountID: "test-account",
		ServiceID: "test-service",
		Target:    backendLn.Addr().String(),
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = router.Serve(ctx, ln) }()

	// Plain TCP (non-TLS) connection should be relayed via fallback.
	// Use exactly 5 bytes. PeekClientHello reads 5 bytes as the TLS
	// header, so a single 5-byte write lands as one chunk at the backend.
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	testData := []byte("hello")
	_, err = conn.Write(testData)
	require.NoError(t, err)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, testData, buf[:n], "should receive echoed data through fallback relay")
}

func TestPortRouter_FallbackOnUnknownSNI(t *testing.T) {
	// Backend TLS echo server.
	backendCert := generateSelfSignedCert(t)
	backendLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{backendCert},
	})
	require.NoError(t, err)
	defer backendLn.Close()

	go func() {
		conn, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(buf[:n])
	}()

	dialResolve := func(_ types.AccountID) (types.DialContextFunc, error) {
		return func(_ context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, address)
		}, nil
	}

	logger := log.StandardLogger()
	router := NewPortRouter(logger, dialResolve)
	// Only a fallback, no SNI route for "unknown.example.com".
	router.SetFallback(Route{
		Type:      RouteTCP,
		AccountID: "test-account",
		ServiceID: "test-service",
		Target:    backendLn.Addr().String(),
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = router.Serve(ctx, ln) }()

	// TLS with unknown SNI → fallback relay to TLS backend.
	tlsConn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName:         "tcp.example.com",
		InsecureSkipVerify: true, //nolint:gosec
	})
	require.NoError(t, err)
	defer tlsConn.Close()

	testData := []byte("hello through fallback TLS")
	_, err = tlsConn.Write(testData)
	require.NoError(t, err)

	buf := make([]byte, 1024)
	n, err := tlsConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, testData, buf[:n], "unknown SNI should relay through fallback")
}

func TestPortRouter_SNIWinsOverFallback(t *testing.T) {
	// Two backend echo servers: one for SNI match, one for fallback.
	sniBacked := startEchoTLS(t)
	fbBacked := startEchoTLS(t)

	dialResolve := func(_ types.AccountID) (types.DialContextFunc, error) {
		return func(_ context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, address)
		}, nil
	}

	logger := log.StandardLogger()
	router := NewPortRouter(logger, dialResolve)
	router.AddRoute("tcp.example.com", Route{
		Type:      RouteTCP,
		AccountID: "test-account",
		ServiceID: "sni-service",
		Target:    sniBacked.Addr().String(),
	})
	router.SetFallback(Route{
		Type:      RouteTCP,
		AccountID: "test-account",
		ServiceID: "fb-service",
		Target:    fbBacked.Addr().String(),
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = router.Serve(ctx, ln) }()

	// TLS with matching SNI should go to SNI backend, not fallback.
	tlsConn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName:         "tcp.example.com",
		InsecureSkipVerify: true, //nolint:gosec
	})
	require.NoError(t, err)
	defer tlsConn.Close()

	testData := []byte("SNI route data")
	_, err = tlsConn.Write(testData)
	require.NoError(t, err)

	buf := make([]byte, 1024)
	n, err := tlsConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, testData, buf[:n], "SNI match should use SNI route, not fallback")
}

func TestPortRouter_NoFallbackNoHTTP_Closes(t *testing.T) {
	logger := log.StandardLogger()
	router := NewPortRouter(logger, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = router.Serve(ctx, ln) }()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	_, _ = conn.Write([]byte("hello"))

	// Connection should be closed by the router (no fallback, no HTTP).
	buf := make([]byte, 1)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = conn.Read(buf)
	assert.Error(t, err, "connection should be closed when no fallback and no HTTP channel")
}

func TestRouter_FallbackAndHTTPCoexist(t *testing.T) {
	// Fallback backend echo server (plain TCP).
	fbBackend, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer fbBackend.Close()

	go func() {
		conn, err := fbBackend.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		_, _ = conn.Write(buf[:n])
	}()

	dialResolve := func(_ types.AccountID) (types.DialContextFunc, error) {
		return func(_ context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, address)
		}, nil
	}

	logger := log.StandardLogger()
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	router := NewRouter(logger, dialResolve, addr)

	// HTTP route for known SNI.
	router.AddRoute("app.example.com", Route{Type: RouteHTTP})
	// Fallback for non-TLS / unknown SNI.
	router.SetFallback(Route{
		Type:      RouteTCP,
		AccountID: "test-account",
		ServiceID: "fb-service",
		Target:    fbBackend.Addr().String(),
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = router.Serve(ctx, ln) }()

	// 1. TLS with known HTTP SNI → should go to HTTP channel.
	go func() {
		conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
		if err != nil {
			return
		}
		c := tls.Client(conn, &tls.Config{
			ServerName:         "app.example.com",
			InsecureSkipVerify: true, //nolint:gosec
		})
		_ = c.Handshake()
		c.Close()
	}()

	select {
	case httpConn := <-router.httpCh:
		assert.NotNil(t, httpConn, "known HTTP SNI should go to HTTP channel")
		httpConn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP-route connection was not delivered to HTTP handler")
	}

	// 2. Plain TCP (non-TLS) → should go to fallback, not HTTP.
	// Use exactly 5 bytes to match PeekClientHello header size.
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	testData := []byte("plain")
	_, err = conn.Write(testData)
	require.NoError(t, err)

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, testData, buf[:n], "non-TLS should be relayed via fallback, not HTTP")
}

// startEchoTLS starts a TLS echo server and returns the listener.
func startEchoTLS(t *testing.T) net.Listener {
	t.Helper()

	cert := generateSelfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return
			}
		}
	}()

	return ln
}

func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"tcp.example.com"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}

func TestRouter_DrainWaitsForRelays(t *testing.T) {
	logger := log.StandardLogger()
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer backendLn.Close()

	// Accept connections: echo first message, then hold open until told to close.
	closeBackend := make(chan struct{})
	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				_, _ = c.Write(buf[:n])
				<-closeBackend
			}(conn)
		}
	}()

	dialResolve := func(_ types.AccountID) (types.DialContextFunc, error) {
		return (&net.Dialer{}).DialContext, nil
	}

	router := NewPortRouter(logger, dialResolve)
	router.SetFallback(Route{
		Type:   RouteTCP,
		Target: backendLn.Addr().String(),
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	go func() {
		_ = router.Serve(ctx, ln)
		close(serveDone)
	}()

	// Open a relay connection (non-TLS, hits fallback).
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	_, _ = conn.Write([]byte("hello"))

	// Wait for the echo to confirm the relay is fully established.
	buf := make([]byte, 16)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf[:n]))
	_ = conn.SetReadDeadline(time.Time{})

	// Drain with a short timeout should fail because the relay is still active.
	assert.False(t, router.Drain(50*time.Millisecond), "drain should timeout with active relay")

	// Close backend connections so relays finish.
	close(closeBackend)
	_ = conn.Close()

	// Drain should now complete quickly.
	assert.True(t, router.Drain(2*time.Second), "drain should succeed after relays end")

	cancel()
	<-serveDone
}

func TestRouter_DrainEmptyReturnsImmediately(t *testing.T) {
	logger := log.StandardLogger()
	router := NewPortRouter(logger, nil)

	start := time.Now()
	ok := router.Drain(5 * time.Second)
	elapsed := time.Since(start)

	assert.True(t, ok)
	assert.Less(t, elapsed, 100*time.Millisecond, "drain with no relays should return immediately")
}

// TestRemoveRoute_KillsActiveRelays verifies that removing a route
// immediately kills active relay connections for that service.
func TestRemoveRoute_KillsActiveRelays(t *testing.T) {
	backendLn, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer backendLn.Close()

	// Backend echoes first message, then holds connection open.
	go func() {
		for {
			conn, err := backendLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				_, _ = c.Write(buf[:n])
				// Hold the connection open.
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	dialResolve := func(_ types.AccountID) (types.DialContextFunc, error) {
		return (&net.Dialer{}).DialContext, nil
	}

	logger := log.StandardLogger()
	router := NewPortRouter(logger, dialResolve)
	router.SetFallback(Route{
		Type:      RouteTCP,
		ServiceID: "svc-1",
		Target:    backendLn.Addr().String(),
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = router.Serve(ctx, ln) }()

	// Establish a relay connection.
	conn, err := net.Dial("tcp", ln.Addr().String())
	require.NoError(t, err)
	defer conn.Close()
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)

	// Wait for echo to confirm relay is established.
	buf := make([]byte, 16)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf[:n]))
	_ = conn.SetReadDeadline(time.Time{})

	// Remove the fallback: should kill the active relay.
	router.RemoveFallback("svc-1")

	// The client connection should see an error (server closed).
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(buf)
	assert.Error(t, err, "connection should be killed after service removal")
}

// TestRemoveRoute_KillsSNIRelays verifies that removing an SNI route
// kills its active relays without affecting other services.
func TestRemoveRoute_KillsSNIRelays(t *testing.T) {
	backend := startEchoTLS(t)
	defer backend.Close()

	dialResolve := func(_ types.AccountID) (types.DialContextFunc, error) {
		return (&net.Dialer{}).DialContext, nil
	}

	logger := log.StandardLogger()
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	router := NewRouter(logger, dialResolve, addr)
	router.AddRoute("tls.example.com", Route{
		Type:      RouteTCP,
		ServiceID: "svc-tls",
		Target:    backend.Addr().String(),
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = router.Serve(ctx, ln) }()

	// Establish a TLS relay.
	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp", ln.Addr().String(),
		&tls.Config{ServerName: "tls.example.com", InsecureSkipVerify: true},
	)
	require.NoError(t, err)
	defer tlsConn.Close()

	_, err = tlsConn.Write([]byte("ping"))
	require.NoError(t, err)
	buf := make([]byte, 1024)
	n, err := tlsConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf[:n]))

	// Remove the route: active relay should die.
	router.RemoveRoute("tls.example.com", "svc-tls")

	_ = tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = tlsConn.Read(buf)
	assert.Error(t, err, "TLS relay should be killed after route removal")
}

// TestPortRouter_SNIAndTCPFallbackCoexist verifies that a single port can
// serve both SNI-routed TLS passthrough and plain TCP fallback simultaneously.
func TestPortRouter_SNIAndTCPFallbackCoexist(t *testing.T) {
	sniBackend := startEchoTLS(t)
	fbBackend := startEchoPlain(t)

	dialResolve := func(_ types.AccountID) (types.DialContextFunc, error) {
		return func(_ context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, address)
		}, nil
	}

	logger := log.StandardLogger()
	router := NewPortRouter(logger, dialResolve)

	// SNI route for a specific domain.
	router.AddRoute("tcp.example.com", Route{
		Type:      RouteTCP,
		AccountID: "acct-1",
		ServiceID: "svc-sni",
		Target:    sniBackend.Addr().String(),
	})
	// TCP fallback for everything else.
	router.SetFallback(Route{
		Type:      RouteTCP,
		AccountID: "acct-2",
		ServiceID: "svc-fb",
		Target:    fbBackend.Addr().String(),
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = router.Serve(ctx, ln) }()

	// 1. TLS with matching SNI → goes to SNI backend.
	tlsConn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName:         "tcp.example.com",
		InsecureSkipVerify: true, //nolint:gosec
	})
	require.NoError(t, err)

	_, err = tlsConn.Write([]byte("sni-data"))
	require.NoError(t, err)
	buf := make([]byte, 1024)
	n, err := tlsConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "sni-data", string(buf[:n]), "SNI match → SNI backend")
	tlsConn.Close()

	// 2. Plain TCP (no TLS) → goes to fallback.
	tcpConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	require.NoError(t, err)

	_, err = tcpConn.Write([]byte("plain"))
	require.NoError(t, err)
	n, err = tcpConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "plain", string(buf[:n]), "plain TCP → fallback backend")
	tcpConn.Close()

	// 3. TLS with unknown SNI → also goes to fallback.
	unknownBackend := startEchoTLS(t)
	router.SetFallback(Route{
		Type:      RouteTCP,
		AccountID: "acct-2",
		ServiceID: "svc-fb",
		Target:    unknownBackend.Addr().String(),
	})

	unknownTLS, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName:         "unknown.example.com",
		InsecureSkipVerify: true, //nolint:gosec
	})
	require.NoError(t, err)

	_, err = unknownTLS.Write([]byte("unknown-sni"))
	require.NoError(t, err)
	n, err = unknownTLS.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "unknown-sni", string(buf[:n]), "unknown SNI → fallback backend")
	unknownTLS.Close()
}

// TestPortRouter_UpdateRouteSwapsSNI verifies that updating a route
// (remove + add with different target) correctly routes to the new backend.
func TestPortRouter_UpdateRouteSwapsSNI(t *testing.T) {
	backend1 := startEchoTLS(t)
	backend2 := startEchoTLS(t)

	dialResolve := func(_ types.AccountID) (types.DialContextFunc, error) {
		return func(_ context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, address)
		}, nil
	}

	logger := log.StandardLogger()
	router := NewPortRouter(logger, dialResolve)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = router.Serve(ctx, ln) }()

	// Initial route → backend1.
	router.AddRoute("db.example.com", Route{
		Type:      RouteTCP,
		ServiceID: "svc-db",
		Target:    backend1.Addr().String(),
	})

	conn1, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName:         "db.example.com",
		InsecureSkipVerify: true, //nolint:gosec
	})
	require.NoError(t, err)
	_, err = conn1.Write([]byte("v1"))
	require.NoError(t, err)
	buf := make([]byte, 1024)
	n, err := conn1.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "v1", string(buf[:n]))
	conn1.Close()

	// Update: remove old route, add new → backend2.
	router.RemoveRoute("db.example.com", "svc-db")
	router.AddRoute("db.example.com", Route{
		Type:      RouteTCP,
		ServiceID: "svc-db",
		Target:    backend2.Addr().String(),
	})

	conn2, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName:         "db.example.com",
		InsecureSkipVerify: true, //nolint:gosec
	})
	require.NoError(t, err)
	_, err = conn2.Write([]byte("v2"))
	require.NoError(t, err)
	n, err = conn2.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "v2", string(buf[:n]))
	conn2.Close()
}

// TestPortRouter_RemoveSNIFallsThrough verifies that after removing an
// SNI route, connections for that domain fall through to the fallback.
func TestPortRouter_RemoveSNIFallsThrough(t *testing.T) {
	sniBackend := startEchoTLS(t)
	fbBackend := startEchoTLS(t)

	dialResolve := func(_ types.AccountID) (types.DialContextFunc, error) {
		return func(_ context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, address)
		}, nil
	}

	logger := log.StandardLogger()
	router := NewPortRouter(logger, dialResolve)
	router.AddRoute("db.example.com", Route{
		Type:      RouteTCP,
		ServiceID: "svc-db",
		Target:    sniBackend.Addr().String(),
	})
	router.SetFallback(Route{
		Type:   RouteTCP,
		Target: fbBackend.Addr().String(),
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = router.Serve(ctx, ln) }()

	// Before removal: SNI matches → sniBackend.
	conn1, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName:         "db.example.com",
		InsecureSkipVerify: true, //nolint:gosec
	})
	require.NoError(t, err)
	_, err = conn1.Write([]byte("before"))
	require.NoError(t, err)
	buf := make([]byte, 1024)
	n, err := conn1.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "before", string(buf[:n]))
	conn1.Close()

	// Remove SNI route. Should fall through to fallback.
	router.RemoveRoute("db.example.com", "svc-db")

	conn2, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{
		ServerName:         "db.example.com",
		InsecureSkipVerify: true, //nolint:gosec
	})
	require.NoError(t, err)
	_, err = conn2.Write([]byte("after"))
	require.NoError(t, err)
	n, err = conn2.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "after", string(buf[:n]), "after removal, should reach fallback")
	conn2.Close()
}

// TestPortRouter_RemoveFallbackCloses verifies that after removing the
// fallback, non-matching connections are closed.
func TestPortRouter_RemoveFallbackCloses(t *testing.T) {
	fbBackend := startEchoPlain(t)

	dialResolve := func(_ types.AccountID) (types.DialContextFunc, error) {
		return func(_ context.Context, network, address string) (net.Conn, error) {
			return net.Dial(network, address)
		}, nil
	}

	logger := log.StandardLogger()
	router := NewPortRouter(logger, dialResolve)
	router.SetFallback(Route{
		Type:      RouteTCP,
		ServiceID: "svc-fb",
		Target:    fbBackend.Addr().String(),
	})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = router.Serve(ctx, ln) }()

	// With fallback: plain TCP works.
	conn1, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	require.NoError(t, err)
	_, err = conn1.Write([]byte("hello"))
	require.NoError(t, err)
	buf := make([]byte, 1024)
	n, err := conn1.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf[:n]))
	conn1.Close()

	// Remove fallback.
	router.RemoveFallback("svc-fb")

	// Without fallback on a port router (no HTTP channel): connection should be closed.
	conn2, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	require.NoError(t, err)
	defer conn2.Close()
	_, _ = conn2.Write([]byte("bye"))
	_ = conn2.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = conn2.Read(buf)
	assert.Error(t, err, "without fallback, connection should be closed")
}

// TestPortRouter_HTTPToTLSTransition verifies that switching a service from
// HTTP-only to TLS-only via remove+add doesn't orphan the old HTTP route.
func TestPortRouter_HTTPToTLSTransition(t *testing.T) {
	logger := log.StandardLogger()
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	tlsBackend := startEchoTLS(t)

	dialResolve := func(_ types.AccountID) (types.DialContextFunc, error) {
		return (&net.Dialer{}).DialContext, nil
	}

	router := NewRouter(logger, dialResolve, addr)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = router.Serve(ctx, ln) }()

	// Phase 1: HTTP-only. SNI connections go to HTTP channel.
	router.AddRoute("app.example.com", Route{Type: RouteHTTP, AccountID: "acct-1", ServiceID: "svc-1"})

	httpConn := router.HTTPListener()
	connDone := make(chan struct{})
	go func() {
		defer close(connDone)
		c, err := httpConn.Accept()
		if err == nil {
			c.Close()
		}
	}()
	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp", ln.Addr().String(),
		&tls.Config{ServerName: "app.example.com", InsecureSkipVerify: true},
	)
	if err == nil {
		tlsConn.Close()
	}
	select {
	case <-connDone:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP listener did not receive connection for HTTP-only route")
	}

	// Phase 2: Simulate update to TLS-only (removeMapping + addMapping).
	router.RemoveRoute("app.example.com", "svc-1")
	router.AddRoute("app.example.com", Route{
		Type:      RouteTCP,
		AccountID: "acct-1",
		ServiceID: "svc-1",
		Target:    tlsBackend.Addr().String(),
	})

	tlsConn2, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp", ln.Addr().String(),
		&tls.Config{ServerName: "app.example.com", InsecureSkipVerify: true},
	)
	require.NoError(t, err, "TLS connection should succeed after HTTP→TLS transition")
	defer tlsConn2.Close()

	_, err = tlsConn2.Write([]byte("hello-tls"))
	require.NoError(t, err)
	buf := make([]byte, 1024)
	n, err := tlsConn2.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "hello-tls", string(buf[:n]), "data should relay to TLS backend")
}

// TestPortRouter_TLSToHTTPTransition verifies that switching a service from
// TLS-only to HTTP-only via remove+add doesn't orphan the old TLS route.
func TestPortRouter_TLSToHTTPTransition(t *testing.T) {
	logger := log.StandardLogger()
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	tlsBackend := startEchoTLS(t)

	dialResolve := func(_ types.AccountID) (types.DialContextFunc, error) {
		return (&net.Dialer{}).DialContext, nil
	}

	router := NewRouter(logger, dialResolve, addr)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = router.Serve(ctx, ln) }()

	// Phase 1: TLS-only. Route relays to backend.
	router.AddRoute("app.example.com", Route{
		Type:      RouteTCP,
		AccountID: "acct-1",
		ServiceID: "svc-1",
		Target:    tlsBackend.Addr().String(),
	})

	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp", ln.Addr().String(),
		&tls.Config{ServerName: "app.example.com", InsecureSkipVerify: true},
	)
	require.NoError(t, err, "TLS relay should work before transition")
	_, err = tlsConn.Write([]byte("tls-data"))
	require.NoError(t, err)
	buf := make([]byte, 1024)
	n, err := tlsConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "tls-data", string(buf[:n]))
	tlsConn.Close()

	// Phase 2: Simulate update to HTTP-only (removeMapping + addMapping).
	router.RemoveRoute("app.example.com", "svc-1")
	router.AddRoute("app.example.com", Route{Type: RouteHTTP, AccountID: "acct-1", ServiceID: "svc-1"})

	// TLS connection should now go to the HTTP listener, NOT to the old TLS backend.
	httpConn := router.HTTPListener()
	connDone := make(chan struct{})
	go func() {
		defer close(connDone)
		c, err := httpConn.Accept()
		if err == nil {
			c.Close()
		}
	}()
	tlsConn2, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp", ln.Addr().String(),
		&tls.Config{ServerName: "app.example.com", InsecureSkipVerify: true},
	)
	if err == nil {
		tlsConn2.Close()
	}
	select {
	case <-connDone:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP listener should receive connection after TLS→HTTP transition")
	}
}

// TestPortRouter_MultiDomainSamePort verifies that two TLS services sharing
// the same port router are independently routable and removable.
func TestPortRouter_MultiDomainSamePort(t *testing.T) {
	logger := log.StandardLogger()
	backend1 := startEchoTLSMulti(t)
	backend2 := startEchoTLSMulti(t)

	dialResolve := func(_ types.AccountID) (types.DialContextFunc, error) {
		return (&net.Dialer{}).DialContext, nil
	}

	router := NewPortRouter(logger, dialResolve)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = router.Serve(ctx, ln) }()

	router.AddRoute("svc1.example.com", Route{Type: RouteTCP, AccountID: "acct-1", ServiceID: "svc-1", Target: backend1.Addr().String()})
	router.AddRoute("svc2.example.com", Route{Type: RouteTCP, AccountID: "acct-1", ServiceID: "svc-2", Target: backend2.Addr().String()})
	assert.False(t, router.IsEmpty())

	// Both domains route independently.
	for _, tc := range []struct {
		sni  string
		data string
	}{
		{"svc1.example.com", "hello-svc1"},
		{"svc2.example.com", "hello-svc2"},
	} {
		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 2 * time.Second},
			"tcp", ln.Addr().String(),
			&tls.Config{ServerName: tc.sni, InsecureSkipVerify: true},
		)
		require.NoError(t, err, "dial %s", tc.sni)
		_, err = conn.Write([]byte(tc.data))
		require.NoError(t, err)
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		require.NoError(t, err)
		assert.Equal(t, tc.data, string(buf[:n]))
		conn.Close()
	}

	// Remove svc1. Router should NOT be empty (svc2 still present).
	router.RemoveRoute("svc1.example.com", "svc-1")
	assert.False(t, router.IsEmpty(), "router should not be empty with one route remaining")

	// svc2 still works.
	conn2, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp", ln.Addr().String(),
		&tls.Config{ServerName: "svc2.example.com", InsecureSkipVerify: true},
	)
	require.NoError(t, err)
	_, err = conn2.Write([]byte("still-alive"))
	require.NoError(t, err)
	buf := make([]byte, 1024)
	n, err := conn2.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "still-alive", string(buf[:n]))
	conn2.Close()

	// Remove svc2. Router is now empty.
	router.RemoveRoute("svc2.example.com", "svc-2")
	assert.True(t, router.IsEmpty(), "router should be empty after removing all routes")
}

// TestPortRouter_SNIAndFallbackLifecycle verifies the full lifecycle of SNI
// routes and TCP fallback coexisting on the same port router, including the
// ordering of add/remove operations.
func TestPortRouter_SNIAndFallbackLifecycle(t *testing.T) {
	logger := log.StandardLogger()
	sniBackend := startEchoTLS(t)
	fallbackBackend := startEchoPlain(t)

	dialResolve := func(_ types.AccountID) (types.DialContextFunc, error) {
		return (&net.Dialer{}).DialContext, nil
	}

	router := NewPortRouter(logger, dialResolve)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = router.Serve(ctx, ln) }()

	// Step 1: Add fallback first (port mapping), then SNI route (TLS service).
	router.SetFallback(Route{Type: RouteTCP, AccountID: "acct-1", ServiceID: "pm-1", Target: fallbackBackend.Addr().String()})
	router.AddRoute("tls.example.com", Route{Type: RouteTCP, AccountID: "acct-1", ServiceID: "svc-1", Target: sniBackend.Addr().String()})
	assert.False(t, router.IsEmpty())

	// SNI traffic goes to TLS backend.
	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 2 * time.Second},
		"tcp", ln.Addr().String(),
		&tls.Config{ServerName: "tls.example.com", InsecureSkipVerify: true},
	)
	require.NoError(t, err)
	_, err = tlsConn.Write([]byte("sni-traffic"))
	require.NoError(t, err)
	buf := make([]byte, 1024)
	n, err := tlsConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "sni-traffic", string(buf[:n]))
	tlsConn.Close()

	// Plain TCP goes to fallback.
	plainConn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	require.NoError(t, err)
	_, err = plainConn.Write([]byte("plain"))
	require.NoError(t, err)
	n, err = plainConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "plain", string(buf[:n]))
	plainConn.Close()

	// Step 2: Remove SNI route. Fallback still works, router not empty.
	router.RemoveRoute("tls.example.com", "svc-1")
	assert.False(t, router.IsEmpty(), "fallback still present")

	plainConn2, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	require.NoError(t, err)
	// Must send >= 5 bytes so the SNI peek completes immediately
	// without waiting for the 5-second peek timeout.
	_, err = plainConn2.Write([]byte("after"))
	require.NoError(t, err)
	n, err = plainConn2.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, "after", string(buf[:n]))
	plainConn2.Close()

	// Step 3: Remove fallback. Router is now empty.
	router.RemoveFallback("pm-1")
	assert.True(t, router.IsEmpty())
}

// TestPortRouter_IsEmptyTransitions verifies IsEmpty reflects correct state
// through all add/remove operations.
func TestPortRouter_IsEmptyTransitions(t *testing.T) {
	logger := log.StandardLogger()
	router := NewPortRouter(logger, nil)

	assert.True(t, router.IsEmpty(), "new router")

	router.AddRoute("a.com", Route{Type: RouteTCP, ServiceID: "svc-a"})
	assert.False(t, router.IsEmpty(), "after adding route")

	router.SetFallback(Route{Type: RouteTCP, ServiceID: "svc-fb1"})
	assert.False(t, router.IsEmpty(), "route + fallback")

	router.RemoveRoute("a.com", "svc-a")
	assert.False(t, router.IsEmpty(), "fallback only")

	router.RemoveFallback("svc-fb1")
	assert.True(t, router.IsEmpty(), "all removed")

	// Reverse order: fallback first, then route.
	router.SetFallback(Route{Type: RouteTCP, ServiceID: "svc-fb2"})
	assert.False(t, router.IsEmpty())

	router.AddRoute("b.com", Route{Type: RouteTCP, ServiceID: "svc-b"})
	assert.False(t, router.IsEmpty())

	router.RemoveFallback("svc-fb2")
	assert.False(t, router.IsEmpty(), "route still present")

	router.RemoveRoute("b.com", "svc-b")
	assert.True(t, router.IsEmpty(), "fully empty again")
}

// startEchoTLSMulti starts a TLS echo server that accepts multiple connections.
func startEchoTLSMulti(t *testing.T) net.Listener {
	t.Helper()

	cert := generateSelfSignedCert(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				_, _ = c.Write(buf[:n])
			}(conn)
		}
	}()

	return ln
}

// startEchoPlain starts a plain TCP echo server that reads until newline
// or connection close, then echoes the received data.
func startEchoPlain(t *testing.T) net.Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Set a read deadline so we don't block forever waiting for more data.
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				_, _ = c.Write(buf[:n])
			}(conn)
		}
	}()

	return ln
}

// fakeAddr implements net.Addr with a custom string representation.
type fakeAddr string

func (f fakeAddr) Network() string { return "tcp" }
func (f fakeAddr) String() string  { return string(f) }

// fakeConn is a minimal net.Conn with a controllable RemoteAddr.
type fakeConn struct {
	net.Conn
	remote net.Addr
}

func (f *fakeConn) RemoteAddr() net.Addr { return f.remote }

func TestCheckRestrictions_UnparseableAddress(t *testing.T) {
	router := NewPortRouter(log.StandardLogger(), nil)
	filter := restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}})
	route := Route{Filter: filter}

	conn := &fakeConn{remote: fakeAddr("not-an-ip")}
	assert.NotEqual(t, restrict.Allow, router.checkRestrictions(conn, route), "unparsable address must be denied")
}

func TestCheckRestrictions_NilRemoteAddr(t *testing.T) {
	router := NewPortRouter(log.StandardLogger(), nil)
	filter := restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}})
	route := Route{Filter: filter}

	conn := &fakeConn{remote: nil}
	assert.NotEqual(t, restrict.Allow, router.checkRestrictions(conn, route), "nil remote address must be denied")
}

func TestCheckRestrictions_AllowedAndDenied(t *testing.T) {
	router := NewPortRouter(log.StandardLogger(), nil)
	filter := restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}})
	route := Route{Filter: filter}

	allowed := &fakeConn{remote: &net.TCPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 1234}}
	assert.Equal(t, restrict.Allow, router.checkRestrictions(allowed, route), "10.1.2.3 in allowlist")

	denied := &fakeConn{remote: &net.TCPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 1234}}
	assert.NotEqual(t, restrict.Allow, router.checkRestrictions(denied, route), "192.168.1.1 not in allowlist")
}

func TestCheckRestrictions_NilFilter(t *testing.T) {
	router := NewPortRouter(log.StandardLogger(), nil)
	route := Route{Filter: nil}

	conn := &fakeConn{remote: fakeAddr("not-an-ip")}
	assert.Equal(t, restrict.Allow, router.checkRestrictions(conn, route), "nil filter should allow everything")
}

func TestCheckRestrictions_IPv4MappedIPv6(t *testing.T) {
	router := NewPortRouter(log.StandardLogger(), nil)
	filter := restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}})
	route := Route{Filter: filter}

	// net.IPv4() returns a 16-byte v4-in-v6 representation internally.
	// The restriction check must Unmap it to match the v4 CIDR.
	conn := &fakeConn{remote: &net.TCPAddr{IP: net.IPv4(10, 1, 2, 3), Port: 5678}}
	assert.Equal(t, restrict.Allow, router.checkRestrictions(conn, route), "v4-in-v6 TCPAddr must match v4 CIDR")

	// Explicitly v4-mapped-v6 address string.
	conn6 := &fakeConn{remote: fakeAddr("[::ffff:10.1.2.3]:5678")}
	assert.Equal(t, restrict.Allow, router.checkRestrictions(conn6, route), "::ffff:10.1.2.3 must match v4 CIDR")

	connOutside := &fakeConn{remote: fakeAddr("[::ffff:192.168.1.1]:5678")}
	assert.NotEqual(t, restrict.Allow, router.checkRestrictions(connOutside, route), "::ffff:192.168.1.1 not in v4 CIDR")
}
