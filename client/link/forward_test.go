package link

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseForward(t *testing.T) {
	tests := []struct {
		name         string
		spec         string
		wantListen   string
		wantUpstream string
	}{
		{
			name:         "full listen address",
			spec:         "http://127.0.0.1:8080=https://grafana.internal",
			wantListen:   "127.0.0.1:8080",
			wantUpstream: "https://grafana.internal",
		},
		{
			name:         "bare port defaults to loopback",
			spec:         "http://8080=https://grafana.internal",
			wantListen:   "127.0.0.1:8080",
			wantUpstream: "https://grafana.internal",
		},
		{
			name:         "empty host defaults to loopback",
			spec:         "http://:8080=https://grafana.internal",
			wantListen:   "127.0.0.1:8080",
			wantUpstream: "https://grafana.internal",
		},
		{
			name:         "upstream without scheme assumes https",
			spec:         "http://8080=grafana.internal",
			wantListen:   "127.0.0.1:8080",
			wantUpstream: "https://grafana.internal",
		},
		{
			name:         "plain http upstream is preserved",
			spec:         "http://8080=http://grafana.internal:3000",
			wantListen:   "127.0.0.1:8080",
			wantUpstream: "http://grafana.internal:3000",
		},
		{
			name:         "upstream query string survives the separator split",
			spec:         "http://8080=https://grafana.internal/d?orgId=1",
			wantListen:   "127.0.0.1:8080",
			wantUpstream: "https://grafana.internal/d?orgId=1",
		},
		{
			name:         "explicit public bind is parsed, gating happens later",
			spec:         "http://0.0.0.0:8080=https://grafana.internal",
			wantListen:   "0.0.0.0:8080",
			wantUpstream: "https://grafana.internal",
		},
		{
			name:         "ipv6 listen address",
			spec:         "http://[::1]:8080=https://grafana.internal",
			wantListen:   "[::1]:8080",
			wantUpstream: "https://grafana.internal",
		},
		{
			name:         "port zero asks the OS for a free port",
			spec:         "http://0=https://grafana.internal",
			wantListen:   "127.0.0.1:0",
			wantUpstream: "https://grafana.internal",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseForward(tc.spec)
			require.NoError(t, err)
			assert.Equal(t, ProtoHTTP, got.Proto, "scheme should select the HTTP forwarder")
			assert.Equal(t, tc.wantListen, got.Listen, "listen address should be normalized")
			assert.Equal(t, tc.wantUpstream, got.Upstream.String(), "upstream should round-trip")
		})
	}
}

func TestParseForwardErrors(t *testing.T) {
	tests := []struct {
		name    string
		spec    string
		wantMsg string
	}{
		{name: "empty", spec: "", wantMsg: "empty forward spec"},
		{name: "no scheme", spec: "8080=grafana.internal", wantMsg: "missing scheme"},
		{name: "no separator", spec: "http://8080", wantMsg: "missing '='"},
		{name: "unknown scheme", spec: "gopher://8080=grafana.internal", wantMsg: "unknown scheme"},
		{name: "port out of range", spec: "http://70000=grafana.internal", wantMsg: "out of range"},
		{name: "port not a number", spec: "http://http=grafana.internal", wantMsg: "not a number"},
		{name: "missing upstream", spec: "http://8080=", wantMsg: "missing upstream"},
		{name: "bad upstream scheme", spec: "http://8080=ftp://grafana.internal", wantMsg: "must be http or https"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseForward(tc.spec)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantMsg, "error should name the actual problem")
		})
	}
}

// Schemes the grammar reserves for later must fail with a message that says so,
// rather than looking like a typo.
func TestParseForwardPlannedSchemes(t *testing.T) {
	for _, proto := range []string{"tcp", "udp", "socks5"} {
		t.Run(proto, func(t *testing.T) {
			_, err := ParseForward(proto + "://5432=db.internal:5432")
			require.Error(t, err)
			assert.Contains(t, err.Error(), "not supported yet",
				"a reserved scheme should report that it is unimplemented")
		})
	}
}

func TestIsLoopback(t *testing.T) {
	tests := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:8080", true},
		{"127.0.0.53:8080", true},
		{"[::1]:8080", true},
		{"0.0.0.0:8080", false},
		{"192.168.1.10:8080", false},
		{"[::]:8080", false},
		{"not-an-address", false},
	}

	for _, tc := range tests {
		t.Run(tc.addr, func(t *testing.T) {
			assert.Equal(t, tc.want, isLoopback(tc.addr))
		})
	}
}
