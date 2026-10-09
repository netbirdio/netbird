package link

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errDialNotExpected marks a test that must never reach the overlay, so a dial
// that does happen fails the test rather than passing silently.
var errDialNotExpected = errors.New("dial not expected in this test")

func refuseDial(context.Context, string, string) (net.Conn, error) {
	return nil, errDialNotExpected
}

// overlayDialer stands in for the embedded client. It records what the
// forwarder asked to reach and then connects to a local test server, which
// lets the whole proxy path be exercised without a live network.
type overlayDialer struct {
	target string
	calls  atomic.Int64
	asked  atomic.Value
}

func (d *overlayDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	d.calls.Add(1)
	d.asked.Store(addr)
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, d.target)
}

func (d *overlayDialer) lastAsked() string {
	v, _ := d.asked.Load().(string)
	return v
}

// startForwarder wires a forwarder in front of upstream and returns its local
// base URL.
func startForwarder(t *testing.T, upstream *httptest.Server) (string, *overlayDialer) {
	t.Helper()

	upstreamURL, err := url.Parse(upstream.URL)
	require.NoError(t, err)

	// The spec names a hostname that does not resolve on this machine, proving
	// the forwarder hands resolution to the dialer instead of the host.
	fwd, err := ParseForward("http://127.0.0.1:0=http://grafana.internal")
	require.NoError(t, err)

	dialer := &overlayDialer{target: upstreamURL.Host}
	f, err := newHTTPForwarder(fwd, dialer.dial)
	require.NoError(t, err)

	go func() { _ = f.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = f.Close(ctx)
	})

	return "http://" + f.Addr(), dialer
}

func TestForwarderProxiesThroughOverlayDialer(t *testing.T) {
	var gotHost, gotPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotPath = r.Host, r.URL.RequestURI()
		_, _ = io.WriteString(w, "reached upstream")
	}))
	defer upstream.Close()

	base, dialer := startForwarder(t, upstream)

	resp, err := http.Get(base + "/dashboard?orgId=1")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "reached upstream", string(body))
	assert.Equal(t, "/dashboard?orgId=1", gotPath, "path and query should be forwarded unchanged")
	assert.Equal(t, "grafana.internal", gotHost,
		"upstream must see its own Host, not the local bind address")
	assert.Equal(t, int64(1), dialer.calls.Load(), "the overlay dialer should carry the request")
	assert.Equal(t, "grafana.internal:80", dialer.lastAsked(),
		"the overlay dialer should be asked for the upstream name, so it resolves in the tunnel")
}

func TestForwarderForwardsRequestBodyAndMethod(t *testing.T) {
	var gotMethod, gotBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.WriteHeader(http.StatusCreated)
	}))
	defer upstream.Close()

	base, _ := startForwarder(t, upstream)

	resp, err := http.Post(base+"/api", "application/json", strings.NewReader(`{"k":"v"}`))
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusCreated, resp.StatusCode)
	assert.Equal(t, http.MethodPost, gotMethod)
	assert.Equal(t, `{"k":"v"}`, gotBody, "request bodies should reach the upstream intact")
}

// A forward whose upstream cannot be reached must answer 502 rather than hang
// or leak the dial error to the caller.
func TestForwarderReportsUnreachableUpstream(t *testing.T) {
	fwd, err := ParseForward("http://127.0.0.1:0=http://grafana.internal")
	require.NoError(t, err)

	refuse := func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Err: net.UnknownNetworkError("no route in overlay")}
	}
	f, err := newHTTPForwarder(fwd, refuse)
	require.NoError(t, err)
	go func() { _ = f.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = f.Close(ctx)
	})

	resp, err := http.Get("http://" + f.Addr())
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusBadGateway, resp.StatusCode)
}

// Binding must fail at construction so a port clash surfaces before any
// forward is announced as ready.
func TestNewHTTPForwarderReportsBindConflict(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer busy.Close()

	fwd, err := ParseForward("http://" + busy.Addr().String() + "=https://grafana.internal")
	require.NoError(t, err)

	_, err = newHTTPForwarder(fwd, refuseDial)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen on")
}

// A forwarder that was built but never served still owns its socket. The
// bind-all-then-serve path closes earlier forwarders when a later bind fails,
// so Close has to release the port even though Serve never ran.
func TestCloseReleasesAnUnservedListener(t *testing.T) {
	fwd, err := ParseForward("http://127.0.0.1:0=https://grafana.internal")
	require.NoError(t, err)

	f, err := newHTTPForwarder(fwd, refuseDial)
	require.NoError(t, err)
	addr := f.Addr()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, f.Close(ctx))

	// The port is free again only if the listener was actually closed.
	reclaimed, err := net.Listen("tcp", addr)
	require.NoError(t, err, "Close should have released the listener")
	require.NoError(t, reclaimed.Close())
}

// A caller that sends headers and then stalls its body must be cut off.
// ReadHeaderTimeout does not cover the body and IdleTimeout applies only
// between requests, so without the idle read deadline this connection would be
// held open indefinitely.
func TestStalledRequestBodyIsCutOff(t *testing.T) {
	previous := bodyIdleTimeout
	bodyIdleTimeout = 150 * time.Millisecond
	t.Cleanup(func() { bodyIdleTimeout = previous })

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer upstream.Close()

	base, _ := startForwarder(t, upstream)

	conn, err := net.Dial("tcp", strings.TrimPrefix(base, "http://"))
	require.NoError(t, err)
	defer conn.Close()

	// Announce a body, send one byte of it, then go quiet.
	_, err = conn.Write([]byte("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1000\r\n\r\nx"))
	require.NoError(t, err)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(10*time.Second)))
	_, err = io.ReadAll(conn)

	// The server closes the connection rather than waiting on the rest of the
	// body, so the read ends well before the generous deadline above.
	require.NoError(t, err, "the connection should be closed by the server, not time out in the test")
}

func TestRedactSpec(t *testing.T) {
	assert.Equal(t, "http://8080=https://user:xxxxx@a.internal",
		redactSpec("http://8080=https://user:hunter2@a.internal"),
		"a password must not survive into an error message")
	assert.Equal(t, "http://8080=https://a.internal",
		redactSpec("http://8080=https://a.internal"),
		"a spec without credentials should be unchanged")
}

// The error that rejects a credential-bearing upstream quotes the spec, which
// must not carry the password back to the terminal.
func TestParseForwardDoesNotEchoPassword(t *testing.T) {
	_, err := ParseForward("http://8080=https://user:hunter2@a.internal")

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "hunter2", "the password must not appear anywhere in the error")
	assert.Contains(t, err.Error(), "must not carry credentials")
}

// A POST whose body is fully delivered must still receive its whole response,
// even when the upstream takes longer to answer than the body idle timeout.
// The deadline that guards the body must not outlive it.
func TestCompletedUploadGetsFullResponse(t *testing.T) {
	previous := bodyIdleTimeout
	bodyIdleTimeout = 200 * time.Millisecond
	t.Cleanup(func() { bodyIdleTimeout = previous })

	payload := strings.Repeat("y", 4096)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		time.Sleep(600 * time.Millisecond)
		_, _ = io.WriteString(w, payload)
	}))
	defer upstream.Close()

	base, _ := startForwarder(t, upstream)

	resp, err := http.Post(base+"/upload", "text/plain", strings.NewReader(strings.Repeat("x", 2048)))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "the response must not be cut off once the body was fully read")
	assert.Equal(t, len(payload), len(body), "the whole response body should arrive")
}

// A page that points its own hostname at this loopback listener must not be
// able to reach the upstream through it.
func TestLoopbackForwarderRejectsForeignHost(t *testing.T) {
	var reached bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer upstream.Close()

	base, _ := startForwarder(t, upstream)

	req, err := http.NewRequest(http.MethodGet, base, nil)
	require.NoError(t, err)
	req.Host = "attacker.example"

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusMisdirectedRequest, resp.StatusCode)
	assert.False(t, reached, "the upstream must not be reached under a foreign Host")
}

func TestLoopbackForwarderRejectsCrossOrigin(t *testing.T) {
	var reached bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer upstream.Close()

	base, _ := startForwarder(t, upstream)

	req, err := http.NewRequest(http.MethodGet, base, nil)
	require.NoError(t, err)
	req.Header.Set("Origin", "https://attacker.example")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.False(t, reached, "the upstream must not be reached from a cross-site page")
}

// The ordinary local callers must keep working: no Origin at all, and a
// same-origin browser request.
func TestLoopbackForwarderAllowsLocalCallers(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	base, _ := startForwarder(t, upstream)

	for _, origin := range []string{"", "http://" + strings.TrimPrefix(base, "http://")} {
		req, err := http.NewRequest(http.MethodGet, base, nil)
		require.NoError(t, err)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		_ = resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "origin %q should be allowed", origin)
		assert.Equal(t, "ok", string(body))
	}
}

// A malformed upstream fails in the URL parser rather than in the credential
// check, so both error layers have to be redacted.
func TestParseForwardRedactsMalformedUpstream(t *testing.T) {
	for _, spec := range []string{
		"http://8080=https://user:hunter2@a.internal:bad",
		"http://8080=https://user:hunter2@a.internal/%zz",
	} {
		_, err := ParseForward(spec)
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "hunter2",
			"a password must not survive a parse failure either")
	}
}

// An embedded <img> or <script> aimed straight at the loopback address carries
// a loopback Host and no Origin, so Sec-Fetch-Site is the only signal that the
// request came from a page.
func TestLoopbackForwarderRejectsCrossSiteFetch(t *testing.T) {
	for _, site := range []string{"cross-site", "same-site", "Cross-Site"} {
		var reached bool
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
		}))

		base, _ := startForwarder(t, upstream)

		req, err := http.NewRequest(http.MethodGet, base, nil)
		require.NoError(t, err)
		req.Header.Set("Sec-Fetch-Site", site)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		upstream.Close()

		assert.Equal(t, http.StatusForbidden, resp.StatusCode, "Sec-Fetch-Site %q should be refused", site)
		assert.False(t, reached, "the upstream must not be reached from a %s page", site)
	}
}

// A browser reaches the listener legitimately when the user navigated to it or
// when the page it serves calls back into it.
func TestLoopbackForwarderAllowsFirstPartyFetch(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	base, _ := startForwarder(t, upstream)

	for _, site := range []string{"none", "same-origin"} {
		req, err := http.NewRequest(http.MethodGet, base, nil)
		require.NoError(t, err)
		req.Header.Set("Sec-Fetch-Site", site)

		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode, "Sec-Fetch-Site %q should be allowed", site)
	}
}

// A page served from another loopback port is a different origin, however
// local it is.
func TestLoopbackForwarderRejectsAnotherLocalPort(t *testing.T) {
	var reached bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer upstream.Close()

	base, _ := startForwarder(t, upstream)

	req, err := http.NewRequest(http.MethodGet, base, nil)
	require.NoError(t, err)
	req.Header.Set("Origin", "http://localhost:3000")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.False(t, reached, "a page on another local port must not reach the upstream")
}

// A rejected request is never read, so the deadline that bounds an accepted
// upload never arms for it. Closing the connection is what stops the server
// from draining a body the caller stopped sending.
func TestRejectedRequestClosesTheConnection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	base, _ := startForwarder(t, upstream)

	body, writer := io.Pipe()
	t.Cleanup(func() { _ = writer.Close() })

	req, err := http.NewRequest(http.MethodPost, base, body)
	require.NoError(t, err)
	req.Host = "attacker.example"

	// The request is answered on another goroutine, so a server that waits on
	// the stalled body fails the test by timing out rather than hanging it.
	type rejection struct {
		status     int
		closesConn bool
	}
	done := make(chan rejection, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		done <- rejection{status: resp.StatusCode, closesConn: resp.Close}
	}()

	select {
	case got := <-done:
		assert.Equal(t, http.StatusMisdirectedRequest, got.status)
		assert.True(t, got.closesConn, "the server must close a connection it rejected rather than drain the body")
	case <-time.After(5 * time.Second):
		t.Fatal("the rejected request was not answered while its body stalled")
	}
}

// net/url ends the userinfo at the last '@', so a password containing one must
// be redacted whole rather than up to its first '@'.
func TestRedactSpecCoversPasswordWithAtSign(t *testing.T) {
	redacted := redactSpec("http://8080=https://user:pa@ss@a.internal/%zz")

	assert.Equal(t, "http://8080=https://user:xxxxx@a.internal/%zz", redacted)
	assert.NotContains(t, redacted, "ss@a.internal", "no part of the password may survive")
}

func TestParseForwardRedactsPasswordWithAtSign(t *testing.T) {
	_, err := ParseForward("http://8080=https://user:pa@ss@a.internal/%zz")

	require.Error(t, err)
	assert.NotContains(t, err.Error(), "ss@", "no part of the password may reach the error")
}

// stalledBodyProbe sends a request whose declared body is only partly
// delivered and then stops, as a caller holding a connection open would. It
// returns the status line, or an empty string when nothing came back inside
// wait.
//
// It speaks raw HTTP rather than using the client, because the shape that
// matters is an explicit Content-Length the sender never satisfies: a body
// handed to http.Client is sent chunked, which exercises a different path in
// the server's post-handler drain.
func stalledBodyProbe(t *testing.T, addr, host string, wait time.Duration) string {
	t.Helper()

	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err, "connect to the forwarder")
	t.Cleanup(func() { _ = conn.Close() })

	req := fmt.Sprintf("POST / HTTP/1.1\r\nHost: %s\r\nContent-Length: 100\r\n\r\n0123456789", host)
	_, err = conn.Write([]byte(req))
	require.NoError(t, err, "send the partial request")

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(wait)))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}
	return strings.SplitN(string(buf[:n]), "\r\n", 2)[0]
}

// A caller that declares a body and then stops sending must still be answered,
// on every path that does not read it. The server drains an unread body before
// reusing the connection, and that drain has no deadline of its own: whatever
// the forwarder leaves on the connection is what bounds it.
//
// Without this, a few thousand such connections exhaust the forwarder's file
// descriptors while each one holds a goroutine parked in that drain.
func TestStalledRequestBodyIsAnsweredOnEveryPath(t *testing.T) {
	// The dial target refuses, so a request that passes the guard reaches the
	// proxy's error handler instead of an upstream.
	base := serveForward(t, "http://127.0.0.1:0=http://grafana.internal", "127.0.0.1:1")
	addr := strings.TrimPrefix(base, "http://")

	cases := []struct {
		name string
		host string
		want string
	}{
		{
			name: "the guard rejects it",
			host: "attacker.example",
			want: "HTTP/1.1 421 Misdirected Request",
		},
		{
			name: "the overlay dial fails",
			host: "127.0.0.1",
			want: "HTTP/1.1 502 Bad Gateway",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stalledBodyProbe(t, addr, tc.host, 8*time.Second)
			assert.Equal(t, tc.want, got,
				"the caller must be answered rather than left waiting out a drain with no deadline")
		})
	}
}
