package roundtrip

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestMultiTransport_NilEmbeddedAlwaysDirects(t *testing.T) {
	mt := NewMultiTransport(nil, nil)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err)
	resp, err := mt.RoundTrip(req)
	require.NoError(t, err, "nil embedded must fall through to direct without panic")
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}
