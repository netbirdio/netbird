package roundtrip

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsBlockedUpstreamAddr(t *testing.T) {
	blocked := []string{
		"0.0.0.0",
		"0.1.2.3",
		"10.1.2.3",
		"100.64.0.1",
		"100.127.255.254",
		"127.0.0.1",
		"127.255.255.255",
		"169.254.169.254",
		"172.16.0.1",
		"172.31.255.255",
		"192.0.0.170",
		"192.168.1.1",
		"198.18.0.1",
		"224.0.0.1",
		"255.255.255.255",
		"::",
		"::1",
		"::169.254.169.254",
		"::ffff:127.0.0.1",
		"::ffff:169.254.169.254",
		"::ffff:10.0.0.1",
		"64:ff9b::a9fe:a9fe", // NAT64 of 169.254.169.254
		"64:ff9b::a00:1",     // NAT64 of 10.0.0.1
		"64:ff9b:1::1",
		"2002:a9fe:a9fe::1", // 6to4 of 169.254.169.254
		"2002:7f00:1::",     // 6to4 of 127.0.0.1
		"fc00::1",
		"fd00:ec2::254",
		"fe80::1",
		"fe80::1%eth0",
		"fec0::1",
		"ff02::1",
	}
	for _, s := range blocked {
		t.Run("blocks "+s, func(t *testing.T) {
			assert.True(t, isBlockedUpstreamAddr(netip.MustParseAddr(s)))
		})
	}

	allowed := []string{
		"1.1.1.1",
		"8.8.8.8",
		"100.63.255.255",
		"100.128.0.0",
		"172.15.255.255",
		"172.32.0.0",
		"169.253.255.255",
		"2606:4700:4700::1111",
		"::ffff:8.8.8.8",
		"64:ff9b::808:808", // NAT64 of 8.8.8.8
		"2002:808:808::1",  // 6to4 of 8.8.8.8
	}
	for _, s := range allowed {
		t.Run("allows "+s, func(t *testing.T) {
			assert.False(t, isBlockedUpstreamAddr(netip.MustParseAddr(s)))
		})
	}

	assert.True(t, isBlockedUpstreamAddr(netip.Addr{}), "the zero Addr must be refused")
}

func TestGuardUpstreamDial_RejectsUnparsableAddress(t *testing.T) {
	err := guardUpstreamDial(context.Background(), "tcp", "not-an-address", nil)
	assert.ErrorIs(t, err, ErrDirectUpstreamBlocked, "an address the guard cannot parse must fail closed")
}

// TestMultiTransport_BlockPrivateUpstreams exercises the guard end to end
// against a loopback test server: by IP literal and by a hostname that
// resolves to loopback, on both direct branches, and confirms the
// embedded branch is not affected.
func TestMultiTransport_BlockPrivateUpstreams(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "reached")
	}))
	defer srv.Close()

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)
	byName := (&url.URL{Scheme: "http", Host: net.JoinHostPort("localhost", port)}).String()

	directCtx := WithDirectUpstream(context.Background())
	insecureCtx := WithSkipTLSVerify(directCtx)

	// roundTrip returns the response body, so callers never hold one open.
	roundTrip := func(t *testing.T, mt *MultiTransport, ctx context.Context, target string) (string, error) {
		t.Helper()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		require.NoError(t, err)
		resp, err := mt.RoundTrip(req)
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return string(body), nil
	}

	t.Run("enabled refuses loopback", func(t *testing.T) {
		t.Setenv(EnvDirectUpstreamBlockPrivate, "true")
		mt := NewMultiTransport(&stubRoundTripper{body: "embedded"}, nil)

		cases := []struct {
			name   string
			ctx    context.Context
			target string
		}{
			{"direct by IP", directCtx, srv.URL},
			{"direct by hostname", directCtx, byName},
			{"insecure by IP", insecureCtx, srv.URL},
			{"insecure by hostname", insecureCtx, byName},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := roundTrip(t, mt, tc.ctx, tc.target)
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrDirectUpstreamBlocked)
			})
		}
	})

	t.Run("enabled leaves embedded branch alone", func(t *testing.T) {
		t.Setenv(EnvDirectUpstreamBlockPrivate, "true")
		embedded := &stubRoundTripper{body: "embedded"}
		mt := NewMultiTransport(embedded, nil)

		body, err := roundTrip(t, mt, context.Background(), srv.URL)
		require.NoError(t, err)
		assert.Equal(t, "embedded", body)
		assert.True(t, embedded.called, "the guard must not change dispatch to the embedded transport")
	})

	t.Run("disabled by default", func(t *testing.T) {
		mt := NewMultiTransport(&stubRoundTripper{body: "embedded"}, nil)

		body, err := roundTrip(t, mt, directCtx, srv.URL)
		require.NoError(t, err, "private and self-hosted proxies must keep reaching local upstreams")
		assert.Equal(t, "reached", body)
	})
}
