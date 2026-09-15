package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/proxy/internal/proxy"
	"github.com/netbirdio/netbird/proxy/internal/restrict"
	"github.com/netbirdio/netbird/shared/management/proto"
)

// switchableTunnelValidator lets a test flip the ValidateTunnelPeer verdict
// between requests on the same connection. Denials are never cached, so the
// second request always reaches the validator again.
type switchableTunnelValidator struct {
	mu    sync.Mutex
	valid bool
}

func (s *switchableTunnelValidator) setValid(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.valid = v
}

func (s *switchableTunnelValidator) ValidateSession(context.Context, *proto.ValidateSessionRequest, ...grpc.CallOption) (*proto.ValidateSessionResponse, error) {
	return nil, errors.New("not used in this test")
}

func (s *switchableTunnelValidator) ValidateTunnelPeer(context.Context, *proto.ValidateTunnelPeerRequest, ...grpc.CallOption) (*proto.ValidateTunnelPeerResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.valid {
		return &proto.ValidateTunnelPeerResponse{Valid: false, DeniedReason: "not_in_group"}, nil
	}
	return &proto.ValidateTunnelPeerResponse{
		Valid:        true,
		UserId:       "user-1",
		SessionToken: "tunnel-session-token",
	}, nil
}

// The loopback address the test server binds; Protect strips the port
// before looking the domain up, so this is the key AddDomain registers.
const testServerHost = "127.0.0.1"

var testTunnelIP = netip.MustParseAddr("100.90.1.14")

// startProtectedServer runs mw.Protect behind a real listener. Every request is
// stamped the way the overlay listener would stamp it: captured data carrying
// clientIP as the resolved client address and, when lookup is non-nil, a
// tunnel lookup so the tunnel-peer path is reachable.
func startProtectedServer(t *testing.T, mw *Middleware, clientIP netip.Addr, lookup TunnelLookupFunc, h2 bool) *httptest.Server {
	t.Helper()
	protected := mw.Protect(newPassthroughHandler())
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cd := proxy.NewCapturedData("")
		cd.SetClientIP(clientIP)
		ctx := proxy.WithCapturedData(r.Context(), cd)
		ctx = WithTunnelLookup(ctx, lookup)
		protected.ServeHTTP(w, r.WithContext(ctx))
	})

	srv := httptest.NewUnstartedServer(handler)
	if h2 {
		srv.EnableHTTP2 = true
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	return srv
}

// doTraced performs a GET and reports whether the connection that finally
// served it was reused from the client's pool. The body is drained so the
// connection is eligible for reuse afterwards. The last GotConn wins because
// the HTTP/2 transport retries a request cut off by GOAWAY on a new connection
// and reports a second GotConn for that attempt.
func doTraced(t *testing.T, client *http.Client, url string) (*http.Response, bool) {
	t.Helper()
	var reused bool
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) { reused = info.Reused },
	}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(context.Background(), trace), http.MethodGet, url, nil)
	require.NoError(t, err)
	resp, err := client.Do(req)
	require.NoError(t, err)
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	return resp, reused
}

func acceptAllLookup(_ netip.Addr) (PeerIdentity, bool) {
	return PeerIdentity{TunnelIP: testTunnelIP}, true
}

func newPrivateMiddleware(t *testing.T, validator SessionValidator, ipRestrictions *restrict.Filter) *Middleware {
	t.Helper()
	mw := NewMiddleware(log.StandardLogger(), validator, nil)
	kp := generateTestKeyPair(t)
	require.NoError(t, mw.AddDomain(testServerHost, nil, kp.PublicKey, time.Hour, "acct-1", "svc-1", ipRestrictions, true, nil))
	return mw
}

// The primary denial site: a private service whose tunnel peer is rejected
// must emit the exact lowercase "close" token the HTTP/2 server matches on.
func TestProtect_PrivateService_DeniedSetsCloseHeaders(t *testing.T) {
	mw := newPrivateMiddleware(t, &switchableTunnelValidator{}, nil)
	handler := mw.Protect(newPassthroughHandler())

	cd := proxy.NewCapturedData("")
	cd.SetClientIP(testTunnelIP)
	req := httptest.NewRequest(http.MethodGet, "http://"+testServerHost+"/", nil)
	req.RemoteAddr = testTunnelIP.String() + ":5000"
	req = req.WithContext(WithTunnelLookup(proxy.WithCapturedData(req.Context(), cd), acceptAllLookup))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "close", rec.Header().Get("Connection"), "private denial must ask the client to drop the connection")
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"), "private denial must not be cacheable")
}

// A client denied by a private service before it joined the overlay must
// not keep reusing the warm socket, or every retry after connecting keeps
// failing until the idle timeout closes it.
func TestPrivateDeny_HTTP1_ClosesConnection(t *testing.T) {
	validator := &switchableTunnelValidator{}
	mw := newPrivateMiddleware(t, validator, nil)
	srv := startProtectedServer(t, mw, testTunnelIP, acceptAllLookup, false)
	client := srv.Client()

	resp, _ := doTraced(t, client, srv.URL)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Equal(t, 1, resp.ProtoMajor, "plain httptest server must speak HTTP/1.1")
	// The client consumes "Connection: close" into resp.Close and drops the
	// header before returning the response, so that flag is the observable.
	assert.True(t, resp.Close, "private denial must make the client mark the connection as not reusable")
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"), "private denial must not be cacheable")

	validator.setValid(true)
	resp2, reused := doTraced(t, client, srv.URL)
	assert.Equal(t, http.StatusOK, resp2.StatusCode, "the retry must reach the upstream once the peer is valid")
	assert.False(t, reused, "the retry must open a new connection")
}

// On HTTP/2 the server strips the Connection header and answers with GOAWAY
// instead; the client must land its next request on a fresh connection.
func TestPrivateDeny_HTTP2_SendsGoAway(t *testing.T) {
	validator := &switchableTunnelValidator{}
	mw := newPrivateMiddleware(t, validator, nil)
	srv := startProtectedServer(t, mw, testTunnelIP, acceptAllLookup, true)
	client := srv.Client()

	resp, _ := doTraced(t, client, srv.URL)
	require.Equal(t, 2, resp.ProtoMajor, "test client must negotiate HTTP/2")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Connection"), "HTTP/2 must not carry a Connection header on the wire")
	assert.Equal(t, "no-store", resp.Header.Get("Cache-Control"))

	validator.setValid(true)
	resp2, reused := doTraced(t, client, srv.URL)
	assert.Equal(t, 2, resp2.ProtoMajor)
	assert.Equal(t, http.StatusOK, resp2.StatusCode, "the retry must reach the upstream once the peer is valid")
	assert.False(t, reused, "GOAWAY must retire the connection so the retry opens a new one")
}

// Legitimate private traffic keeps its keep-alive connection.
func TestPrivateAllow_KeepsConnection(t *testing.T) {
	validator := &switchableTunnelValidator{valid: true}
	mw := newPrivateMiddleware(t, validator, nil)
	srv := startProtectedServer(t, mw, testTunnelIP, acceptAllLookup, false)
	client := srv.Client()

	resp, _ := doTraced(t, client, srv.URL)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Connection"), "an allowed private request must not close the connection")

	resp2, reused := doTraced(t, client, srv.URL)
	assert.Equal(t, http.StatusOK, resp2.StatusCode)
	assert.True(t, reused, "allowed private traffic must keep reusing the connection")
}

// A public service denial keeps the connection open: only private services
// suffer from the stale-socket problem, so public behaviour is unchanged.
func TestPublicDeny_KeepsConnection(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	filter := restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}})
	require.NoError(t, mw.AddDomain(testServerHost, nil, "", 0, "acct-1", "svc-1", filter, false, nil))
	srv := startProtectedServer(t, mw, netip.MustParseAddr("192.168.1.1"), nil, false)
	client := srv.Client()

	resp, _ := doTraced(t, client, srv.URL)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.Empty(t, resp.Header.Get("Connection"), "public denial must not close the connection")
	assert.Empty(t, resp.Header.Get("Cache-Control"), "public denial must not gain cache headers")

	resp2, reused := doTraced(t, client, srv.URL)
	assert.Equal(t, http.StatusForbidden, resp2.StatusCode)
	assert.True(t, reused, "public denials must keep reusing the connection")
}

// IP restrictions run before the tunnel-peer check, so a private service can
// be denied there too and the client must drop that connection as well.
func TestCheckIPRestrictions_PrivateDenialClosesConnection(t *testing.T) {
	filter := restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"100.64.0.0/16"}})
	mw := newPrivateMiddleware(t, &switchableTunnelValidator{valid: true}, filter)
	handler := mw.Protect(newPassthroughHandler())

	tests := []struct {
		name       string
		remoteAddr string
	}{
		{"denied by CIDR", "100.65.5.6:5000"},
		{"unresolvable client address", "not-an-ip:1234"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://"+testServerHost+"/", nil)
			req.RemoteAddr = tt.remoteAddr
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Equal(t, "close", rec.Header().Get("Connection"), "private IP-restriction denial must close the connection")
			assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"), "private IP-restriction denial must not be cacheable")
		})
	}
}

func TestCheckIPRestrictions_PublicDenialKeepsConnection(t *testing.T) {
	mw := NewMiddleware(log.StandardLogger(), nil, nil)
	filter := restrict.ParseFilter(restrict.FilterConfig{AllowedCIDRs: []string{"10.0.0.0/8"}})
	require.NoError(t, mw.AddDomain(testServerHost, nil, "", 0, "acct-1", "svc-1", filter, false, nil))
	handler := mw.Protect(newPassthroughHandler())

	tests := []struct {
		name       string
		remoteAddr string
	}{
		{"denied by CIDR", "192.168.1.1:5000"},
		{"unresolvable client address", "not-an-ip:1234"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://"+testServerHost+"/", nil)
			req.RemoteAddr = tt.remoteAddr
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Empty(t, rec.Header().Get("Connection"), "public IP-restriction denial must not close the connection")
			assert.Empty(t, rec.Header().Get("Cache-Control"), "public IP-restriction denial must not gain cache headers")
		})
	}
}
