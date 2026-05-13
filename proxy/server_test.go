package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDebugEndpointDisabledByDefault(t *testing.T) {
	s := &Server{}
	assert.False(t, s.DebugEndpointEnabled, "debug endpoint should be disabled by default")
}

func TestParseTargetURL(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantHost     string
		wantHostname string
		wantPort     string
		wantErr      bool
	}{
		{
			name:         "unbracketed ipv6 gets bracketed",
			input:        "http://fb00:cafe:1::3/",
			wantHost:     "[fb00:cafe:1::3]",
			wantHostname: "fb00:cafe:1::3",
			wantPort:     "",
		},
		{
			name:         "bracketed ipv6 is preserved",
			input:        "http://[fb00:cafe:1::3]/",
			wantHost:     "[fb00:cafe:1::3]",
			wantHostname: "fb00:cafe:1::3",
			wantPort:     "",
		},
		{
			name:         "bracketed ipv6 with port is preserved",
			input:        "http://[fb00:cafe:1::3]:8080/",
			wantHost:     "[fb00:cafe:1::3]:8080",
			wantHostname: "fb00:cafe:1::3",
			wantPort:     "8080",
		},
		{
			name:         "ipv4 with port untouched",
			input:        "http://10.0.0.1:8080/",
			wantHost:     "10.0.0.1:8080",
			wantHostname: "10.0.0.1",
			wantPort:     "8080",
		},
		{
			name:         "ipv4 without port untouched",
			input:        "http://10.0.0.1/",
			wantHost:     "10.0.0.1",
			wantHostname: "10.0.0.1",
			wantPort:     "",
		},
		{
			name:         "hostname with port untouched",
			input:        "http://example.com:8080/",
			wantHost:     "example.com:8080",
			wantHostname: "example.com",
			wantPort:     "8080",
		},
		{
			name:         "hostname without port untouched",
			input:        "http://example.com/",
			wantHost:     "example.com",
			wantHostname: "example.com",
			wantPort:     "",
		},
		{
			name:         "full-form 8-group ipv6 gets bracketed",
			input:        "http://fb00:cafe:1:0:0:0:0:3/",
			wantHost:     "[fb00:cafe:1:0:0:0:0:3]",
			wantHostname: "fb00:cafe:1:0:0:0:0:3",
			wantPort:     "",
		},
		{
			name:         "ipv6 loopback unbracketed gets bracketed",
			input:        "http://::1/",
			wantHost:     "[::1]",
			wantHostname: "::1",
			wantPort:     "",
		},
		{
			name:    "malformed url returns error",
			input:   "://not a url",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := parseTargetURL(tc.input)
			if tc.wantErr {
				assert.Error(t, err, "expected parse error")
				return
			}
			require.NoError(t, err, "unexpected parse error")
			assert.Equal(t, tc.wantHost, u.Host, "Host")
			assert.Equal(t, tc.wantHostname, u.Hostname(), "Hostname()")
			assert.Equal(t, tc.wantPort, u.Port(), "Port()")
		})
	}
}

func TestDebugEndpointAddr(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty defaults to localhost",
			input:    "",
			expected: "localhost:8444",
		},
		{
			name:     "explicit localhost preserved",
			input:    "localhost:9999",
			expected: "localhost:9999",
		},
		{
			name:     "explicit address preserved",
			input:    "0.0.0.0:8444",
			expected: "0.0.0.0:8444",
		},
		{
			name:     "127.0.0.1 preserved",
			input:    "127.0.0.1:8444",
			expected: "127.0.0.1:8444",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := debugEndpointAddr(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
