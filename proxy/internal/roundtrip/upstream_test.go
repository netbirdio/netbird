package roundtrip

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http2"
)

// TestUpstreamTransport_AutoFallsBackOnBrokenHTTP2 covers the case ALPN
// cannot express: the upstream advertises h2, picks it, and then cannot
// serve it. The request must still succeed, over HTTP/1.1, and the
// upstream must stay on HTTP/1.1 for the requests that follow.
func TestUpstreamTransport_AutoFallsBackOnBrokenHTTP2(t *testing.T) {
	t.Setenv(EnvUpstreamHTTPVersion, string(upstreamHTTPAuto))
	srv := startBrokenHTTP2Server(t)

	mt := NewDirectOnly(nil)
	ctx := WithSkipTLSVerify(WithDirectUpstream(context.Background()))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+srv.addr, nil)
	require.NoError(t, err)

	resp, err := mt.RoundTrip(req)
	require.NoError(t, err, "a replayable request must be retried on HTTP/1.1 instead of failing")
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	assert.Equal(t, "HTTP/1.1", resp.Proto, "the retry must ride the HTTP/1.1 transport")
	assert.Equal(t, "http/1.1", string(body), "the upstream must see an http/1.1 ALPN offer on the retry")

	assert.True(t, mt.insecure.isDowngraded(srv.addr),
		"the upstream must stay pinned to HTTP/1.1 after proving it cannot serve h2")
	mt.insecure.mu.RLock()
	pin := mt.insecure.downgraded[srv.addr]
	mt.insecure.mu.RUnlock()
	assert.True(t, pin.permanent(),
		"an upstream answering HTTP_1_1_REQUIRED must not be re-probed for h2")

	// The second request must not repeat the h2 attempt: the server
	// counts h2 handshakes, so a repeat would show up here.
	h2Attempts := srv.http2Handshakes()
	req, err = http.NewRequestWithContext(ctx, http.MethodGet, "https://"+srv.addr, nil)
	require.NoError(t, err)
	resp, err = mt.RoundTrip(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, "HTTP/1.1", resp.Proto, "a pinned upstream must go straight to HTTP/1.1")
	assert.Equal(t, h2Attempts, srv.http2Handshakes(),
		"a pinned upstream must not be probed for h2 again until the pin expires")
}

// TestUpstreamTransport_ExplicitHTTP2NeverDowngrades pins the promise
// that the explicit values are absolute: an operator who asked for h2
// keeps h2, broken upstream or not.
func TestUpstreamTransport_ExplicitHTTP2NeverDowngrades(t *testing.T) {
	t.Setenv(EnvUpstreamHTTPVersion, string(upstreamHTTP2))
	srv := startBrokenHTTP2Server(t)

	mt := NewDirectOnly(nil)
	ctx := WithSkipTLSVerify(WithDirectUpstream(context.Background()))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+srv.addr, nil)
	require.NoError(t, err)

	resp, err := mt.RoundTrip(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err, "NB_PROXY_UPSTREAM_HTTP_VERSION=2 must not fall back to HTTP/1.1")
	assert.False(t, mt.insecure.isDowngraded(srv.addr), "an explicit version must never pin an upstream")
}

func TestUpstreamTransport_MayDowngrade(t *testing.T) {
	tests := []struct {
		name    string
		version upstreamHTTPVersion
		url     string
		want    bool
	}{
		{name: "auto over TLS", version: upstreamHTTPAuto, url: "https://backend.invalid", want: true},
		// The proxy speaks no h2c, so a cleartext upstream is already on
		// HTTP/1.1 and its failures say nothing about h2.
		{name: "auto cleartext", version: upstreamHTTPAuto, url: "http://backend.invalid", want: false},
		{name: "explicit 1.1", version: upstreamHTTP11, url: "https://backend.invalid", want: false},
		{name: "explicit 2", version: upstreamHTTP2, url: "https://backend.invalid", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			transport := newUpstreamTransport(&http.Transport{}, tc.version, nil)
			req, err := http.NewRequest(http.MethodGet, tc.url, nil)
			require.NoError(t, err)

			assert.Equal(t, tc.want, transport.mayDowngrade(req))
		})
	}
}

func TestUpstreamTransport_DowngradeExpires(t *testing.T) {
	transport := newUpstreamTransport(&http.Transport{}, upstreamHTTPAuto, nil)
	transport.markDowngraded("backend.invalid:443", false)
	require.True(t, transport.isDowngraded("backend.invalid:443"))

	transport.mu.Lock()
	transport.downgraded["backend.invalid:443"] = downgrade{expiry: time.Now().Add(-time.Second)}
	transport.mu.Unlock()

	assert.False(t, transport.isDowngraded("backend.invalid:443"),
		"an expired pin must let the upstream be offered h2 again")
	transport.mu.RLock()
	_, stillTracked := transport.downgraded["backend.invalid:443"]
	transport.mu.RUnlock()
	assert.False(t, stillTracked, "an expired pin must not be kept around")
}

func TestUpstreamTransport_DowngradeIsPerUpstream(t *testing.T) {
	transport := newUpstreamTransport(&http.Transport{}, upstreamHTTPAuto, nil)
	transport.markDowngraded("broken.invalid:443", false)

	assert.True(t, transport.isDowngraded("broken.invalid:443"))
	assert.False(t, transport.isDowngraded("healthy.invalid:443"),
		"one broken upstream must not drop the others to HTTP/1.1")
}

// TestUpstreamTransport_HTTP11RequiredPinIsPermanent covers the IIS
// case: HTTP_1_1_REQUIRED describes how the upstream is configured
// (Windows Authentication, client certificates), so re-probing it every
// upstreamDowngradeTTL would only buy a failed request per interval.
func TestUpstreamTransport_HTTP11RequiredPinIsPermanent(t *testing.T) {
	transport := newUpstreamTransport(&http.Transport{}, upstreamHTTPAuto, nil)
	transport.markDowngraded("iis.invalid:443", true)

	transport.mu.RLock()
	pin := transport.downgraded["iis.invalid:443"]
	transport.mu.RUnlock()

	assert.True(t, pin.permanent(), "an upstream that asked for HTTP/1.1 must not be re-probed")
	assert.True(t, pin.active(time.Now().Add(100*upstreamDowngradeTTL)),
		"a permanent pin must outlive any TTL")
}

func TestUpstreamTransport_PermanentPinSurvivesLaterFailures(t *testing.T) {
	transport := newUpstreamTransport(&http.Transport{}, upstreamHTTPAuto, nil)
	transport.markDowngraded("iis.invalid:443", true)
	// A later ambiguous failure for the same upstream must not turn the
	// permanent pin into an expiring one.
	transport.markDowngraded("iis.invalid:443", false)

	transport.mu.RLock()
	pin := transport.downgraded["iis.invalid:443"]
	transport.mu.RUnlock()

	assert.True(t, pin.permanent(), "a permanent pin must never be weakened")
}

func TestIsHTTP11Required(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "goaway",
			err:  errors.New(`http2: server sent GOAWAY and closed the connection; LastStreamID=0, ErrCode=HTTP_1_1_REQUIRED, debug=""`),
			want: true,
		},
		{
			name: "stream error",
			err:  http2.StreamError{StreamID: 1, Code: http2.ErrCodeHTTP11Required},
			want: true,
		},
		{
			name: "other h2 failure",
			err:  http2.StreamError{StreamID: 1, Code: http2.ErrCodeProtocol},
			want: false,
		},
		{name: "nil", err: nil, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isHTTP11Required(tc.err))
		})
	}
}

func TestIsHTTP2ProtocolError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "goaway demanding http/1.1",
			err:  errors.New(`http2: server sent GOAWAY and closed the connection; LastStreamID=0, ErrCode=HTTP_1_1_REQUIRED, debug=""`),
			want: true,
		},
		{
			name: "stream error",
			err:  http2.StreamError{StreamID: 1, Code: http2.ErrCodeProtocol},
			want: true,
		},
		{
			name: "connection error",
			err:  http2.ConnectionError(http2.ErrCodeProtocol),
			want: true,
		},
		{
			name: "wrapped h2 error",
			err:  errors.New("Get \"https://backend.invalid\": http2: client connection lost"),
			want: true,
		},
		// Retrying these on HTTP/1.1 fixes nothing, so they must never
		// pin an upstream.
		{name: "dial failure", err: errors.New("dial tcp 10.0.0.1:443: connect: connection refused"), want: false},
		{name: "tls failure", err: errors.New("tls: failed to verify certificate: x509: certificate signed by unknown authority"), want: false},
		{name: "context cancelled", err: context.Canceled, want: false},
		{name: "eof", err: io.EOF, want: false},
		{name: "nil", err: nil, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isHTTP2ProtocolError(tc.err))
		})
	}
}

func TestReplayable(t *testing.T) {
	t.Run("bodyless request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodGet, "https://backend.invalid", nil)
		require.NoError(t, err)

		retry, ok := replayable(req)
		require.True(t, ok)
		assert.Same(t, req, retry, "a bodyless request needs no clone")
	})

	t.Run("request with GetBody", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "https://backend.invalid", strings.NewReader("payload"))
		require.NoError(t, err)
		// Consume the body the way a failed RoundTrip would.
		_, err = io.ReadAll(req.Body)
		require.NoError(t, err)

		retry, ok := replayable(req)
		require.True(t, ok)
		body, err := io.ReadAll(retry.Body)
		require.NoError(t, err)
		assert.Equal(t, "payload", string(body), "the retry must carry a fresh copy of the body")
	})

	t.Run("streamed request", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodPost, "https://backend.invalid", io.NopCloser(strings.NewReader("payload")))
		require.NoError(t, err)
		require.Nil(t, req.GetBody, "an opaque reader must not get a GetBody")

		_, ok := replayable(req)
		assert.False(t, ok, "a body that cannot be regenerated must not be replayed")
	})
}

// brokenHTTP2Server advertises h2 in ALPN, accepts it, and then refuses
// to serve it — the upstream behaviour that motivated the fallback. Over
// http/1.1 it answers normally, so a downgraded request succeeds.
type brokenHTTP2Server struct {
	addr string

	handshakes chan struct{}
}

func (s *brokenHTTP2Server) http2Handshakes() int {
	return len(s.handshakes)
}

func startBrokenHTTP2Server(t *testing.T) *brokenHTTP2Server {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{selfSignedCert(t)},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	srv := &brokenHTTP2Server{
		addr: ln.Addr().String(),
		// Buffered well past what the test drives so a stuck server
		// never blocks the accept loop.
		handshakes: make(chan struct{}, 64),
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go srv.handle(conn)
		}
	}()

	return srv
}

func (s *brokenHTTP2Server) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		return
	}

	if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
		select {
		case s.handshakes <- struct{}{}:
		default:
		}
		s.refuseHTTP2(tlsConn)
		return
	}

	s.serveHTTP1(tlsConn)
}

// refuseHTTP2 completes just enough of the h2 handshake for the client
// to accept the connection, then sends the GOAWAY an upstream uses to
// say the request belongs on HTTP/1.1.
func (s *brokenHTTP2Server) refuseHTTP2(conn net.Conn) {
	framer := http2.NewFramer(conn, conn)
	if err := framer.WriteSettings(); err != nil {
		return
	}
	_ = framer.WriteGoAway(0, http2.ErrCodeHTTP11Required, nil)
}

// serveHTTP1 answers a single request with the protocol the upstream
// saw, so the test can tell which transport carried it.
func (s *brokenHTTP2Server) serveHTTP1(conn net.Conn) {
	reader := bufio.NewReader(conn)
	if _, err := http.ReadRequest(reader); err != nil {
		return
	}

	const body = "http/1.1"
	_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 8\r\nConnection: close\r\n\r\n"+body)
}

func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	require.NoError(t, err)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
