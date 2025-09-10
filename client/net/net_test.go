package net

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetLastIPFromNetwork(t *testing.T) {
	tests := []struct {
		name      string
		network   string
		fromEnd   int
		expected  string
		expectErr bool
	}{
		{
			name:     "IPv4 /24 network - last IP (fromEnd=0)",
			network:  "192.168.1.0/24",
			fromEnd:  0,
			expected: "192.168.1.255",
		},
		{
			name:     "IPv4 /24 network - fromEnd=1",
			network:  "192.168.1.0/24",
			fromEnd:  1,
			expected: "192.168.1.254",
		},
		{
			name:     "IPv4 /24 network - fromEnd=5",
			network:  "192.168.1.0/24",
			fromEnd:  5,
			expected: "192.168.1.250",
		},
		{
			name:     "IPv4 /16 network - last IP",
			network:  "10.0.0.0/16",
			fromEnd:  0,
			expected: "10.0.255.255",
		},
		{
			name:     "IPv4 /16 network - fromEnd=256",
			network:  "10.0.0.0/16",
			fromEnd:  256,
			expected: "10.0.254.255",
		},
		{
			name:     "IPv4 /32 network - single host",
			network:  "192.168.1.100/32",
			fromEnd:  0,
			expected: "192.168.1.100",
		},
		{
			name:     "IPv6 /64 network - last IP",
			network:  "2001:db8::/64",
			fromEnd:  0,
			expected: "2001:db8::ffff:ffff:ffff:ffff",
		},
		{
			name:     "IPv6 /64 network - fromEnd=1",
			network:  "2001:db8::/64",
			fromEnd:  1,
			expected: "2001:db8::ffff:ffff:ffff:fffe",
		},
		{
			name:     "IPv6 /128 network - single host",
			network:  "2001:db8::1/128",
			fromEnd:  0,
			expected: "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			network, err := netip.ParsePrefix(tt.network)
			require.NoError(t, err, "Failed to parse network prefix")

			result, err := GetLastIPFromNetwork(network, tt.fromEnd)

			if tt.expectErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			expectedIP, err := netip.ParseAddr(tt.expected)
			require.NoError(t, err, "Failed to parse expected IP")

			assert.Equal(t, expectedIP, result, "IP mismatch for network %s with fromEnd=%d", tt.network, tt.fromEnd)
		})
	}
}
