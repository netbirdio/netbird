package roundtrip

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubRoundTripper records whether RoundTrip was called and returns a
// canned response so tests can assert the dispatch decision without
// running a real network.
type stubRoundTripper struct {
	called bool
	body   string
}

func (s *stubRoundTripper) RoundTrip(_ *http.Request) (*http.Response, error) {
	s.called = true
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(s.body)),
		Header:     http.Header{},
	}, nil
}

func TestMultiTransport_DispatchesByContextFlag(t *testing.T) {
	embedded := &stubRoundTripper{body: "embedded"}
	mt := NewMultiTransport(embedded, nil)

	t.Run("default routes to embedded", func(t *testing.T) {
		embedded.called = false
		req := httptest.NewRequest(http.MethodGet, "http://example.invalid", nil)
		resp, err := mt.RoundTrip(req)
		require.NoError(t, err, "embedded path must not error on stubbed transport")
		require.NotNil(t, resp)
		_ = resp.Body.Close()
		assert.True(t, embedded.called, "request without WithDirectUpstream must hit the embedded transport")
	})

	t.Run("WithDirectUpstream skips embedded", func(t *testing.T) {
		embedded.called = false
		// Hit a server we control to verify the stdlib transport is used.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(w, "direct")
		}))
		defer srv.Close()

		req, err := http.NewRequestWithContext(WithDirectUpstream(context.Background()), http.MethodGet, srv.URL, nil)
		require.NoError(t, err)
		resp, err := mt.RoundTrip(req)
		require.NoError(t, err, "direct path must dial via stdlib transport")
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.NoError(t, err)
		assert.Equal(t, "direct", string(body), "stdlib transport must reach the test server")
		assert.False(t, embedded.called, "WithDirectUpstream must bypass the embedded transport")
	})
}

// TestMultiTransport_AppliesEnvOverridesToDirect verifies that the
// NB_PROXY_* env vars consumed by loadTransportConfig flow into the
// direct branches (previously they only applied to the embedded
// roundtripper, so direct-upstream traffic ignored operator tuning).
func TestMultiTransport_AppliesEnvOverridesToDirect(t *testing.T) {
	t.Setenv(EnvMaxIdleConns, "42")
	t.Setenv(EnvIdleConnTimeout, "11s")
	t.Setenv(EnvTLSHandshakeTimeout, "7s")

	mt := NewMultiTransport(&stubRoundTripper{body: "embedded"}, nil)

	assert.Equal(t, 42, mt.direct.MaxIdleConns,
		"NB_PROXY_MAX_IDLE_CONNS must propagate to the direct transport")
	assert.Equal(t, 11*time.Second, mt.direct.IdleConnTimeout,
		"NB_PROXY_IDLE_CONN_TIMEOUT must propagate to the direct transport")
	assert.Equal(t, 7*time.Second, mt.direct.TLSHandshakeTimeout,
		"NB_PROXY_TLS_HANDSHAKE_TIMEOUT must propagate to the direct transport")
	assert.Equal(t, 42, mt.insecure.MaxIdleConns,
		"env tuning must also apply to the insecure-skip-verify direct transport")
}

// TestMultiTransport_UpstreamHTTPVersion pins the protocol actually
// negotiated with an HTTPS upstream that offers both h2 and http/1.1.
// The request rides the insecure clone, so this also covers the version
// surviving http.Transport.Clone.
func TestMultiTransport_UpstreamHTTPVersion(t *testing.T) {
	tests := []struct {
		name      string
		env       string
		wantProto string
	}{
		{name: "unset negotiates h2", env: "", wantProto: "HTTP/2.0"},
		{name: "auto negotiates h2", env: "auto", wantProto: "HTTP/2.0"},
		{name: "1.1 pins http/1.1", env: "1.1", wantProto: "HTTP/1.1"},
		{name: "2 negotiates h2", env: "2", wantProto: "HTTP/2.0"},
		{name: "unsupported value keeps the default", env: "http3", wantProto: "HTTP/2.0"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// t.Setenv registers the restore for whatever the process
			// inherited; unsetting afterwards lets the default row
			// exercise a genuinely absent variable.
			t.Setenv(EnvUpstreamHTTPVersion, tc.env)
			if tc.env == "" {
				require.NoError(t, os.Unsetenv(EnvUpstreamHTTPVersion))
			}

			// The test server's certificate isn't in any root pool, so the
			// request rides the insecure branch via WithSkipTLSVerify.
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, r.Proto)
			}))
			srv.EnableHTTP2 = true
			srv.StartTLS()
			defer srv.Close()

			mt := NewDirectOnly(nil)
			ctx := WithSkipTLSVerify(WithDirectUpstream(context.Background()))
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
			require.NoError(t, err)

			resp, err := mt.RoundTrip(req)
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.NoError(t, err)

			assert.Equal(t, tc.wantProto, resp.Proto,
				"client-side protocol must follow %s=%q", EnvUpstreamHTTPVersion, tc.env)
			assert.Equal(t, tc.wantProto, string(body),
				"the upstream must see the same protocol the client negotiated")
		})
	}
}

// TestMultiTransport_NilEmbeddedErrorsWhenWGPathRequested guards
// against the previous silent fallback: a MultiTransport constructed
// without an embedded transport must reject requests that don't
// explicitly opt into the direct branch, rather than routing them
// over the host stack and bypassing WireGuard.
func TestMultiTransport_NilEmbeddedErrorsWhenWGPathRequested(t *testing.T) {
	mt := NewMultiTransport(nil, nil)

	req := httptest.NewRequest(http.MethodGet, "http://example.invalid", nil)
	resp, err := mt.RoundTrip(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err, "nil embedded must surface as an explicit error, not a silent direct dispatch")
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, errNoEmbeddedTransport,
		"the error must be the sentinel so callers can distinguish misconfiguration from network failures")
}

// TestMultiTransport_DirectOnlyServesDirectBranch verifies NewDirectOnly
// constructs a MultiTransport whose direct branch handles requests with
// the direct-upstream flag set, and surfaces the explicit sentinel
// when the embedded path is reached.
func TestMultiTransport_DirectOnlyServesDirectBranch(t *testing.T) {
	mt := NewDirectOnly(nil)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	req, err := http.NewRequestWithContext(WithDirectUpstream(context.Background()), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	resp, err := mt.RoundTrip(req)
	require.NoError(t, err, "direct-only must serve requests that opt into the direct branch")
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	wgReq := httptest.NewRequest(http.MethodGet, "http://example.invalid", nil)
	resp, err = mt.RoundTrip(wgReq)
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err, "direct-only must refuse requests that didn't opt into the direct branch")
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, errNoEmbeddedTransport)
}
