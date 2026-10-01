package link

import (
	"context"
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

	_, err = newHTTPForwarder(fwd, func(context.Context, string, string) (net.Conn, error) {
		return nil, nil
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen on")
}
