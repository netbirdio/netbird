//go:build !android && !ios

package systemops

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsVpnRoute(t *testing.T) {
	tests := []struct {
		name           string
		addr           string
		vpnRoutes      []string
		localRoutes    []string
		expectedVpn    bool
		expectedPrefix netip.Prefix
	}{
		{
			name:           "Match in VPN routes",
			addr:           "192.168.1.1",
			vpnRoutes:      []string{"192.168.1.0/24"},
			localRoutes:    []string{"10.0.0.0/8"},
			expectedVpn:    true,
			expectedPrefix: netip.MustParsePrefix("192.168.1.0/24"),
		},
		{
			name:           "Match in local routes",
			addr:           "10.1.1.1",
			vpnRoutes:      []string{"192.168.1.0/24"},
			localRoutes:    []string{"10.0.0.0/8"},
			expectedVpn:    false,
			expectedPrefix: netip.MustParsePrefix("10.0.0.0/8"),
		},
		{
			name:           "No match",
			addr:           "172.16.0.1",
			vpnRoutes:      []string{"192.168.1.0/24"},
			localRoutes:    []string{"10.0.0.0/8"},
			expectedVpn:    false,
			expectedPrefix: netip.Prefix{},
		},
		{
			name:           "Default route ignored",
			addr:           "192.168.1.1",
			vpnRoutes:      []string{"0.0.0.0/0", "192.168.1.0/24"},
			localRoutes:    []string{"10.0.0.0/8"},
			expectedVpn:    true,
			expectedPrefix: netip.MustParsePrefix("192.168.1.0/24"),
		},
		{
			name:           "Default route matches but ignored",
			addr:           "172.16.1.1",
			vpnRoutes:      []string{"0.0.0.0/0", "192.168.1.0/24"},
			localRoutes:    []string{"10.0.0.0/8"},
			expectedVpn:    false,
			expectedPrefix: netip.Prefix{},
		},
		{
			name:           "Longest prefix match local",
			addr:           "192.168.1.1",
			vpnRoutes:      []string{"192.168.0.0/16"},
			localRoutes:    []string{"192.168.1.0/24"},
			expectedVpn:    false,
			expectedPrefix: netip.MustParsePrefix("192.168.1.0/24"),
		},
		{
			name:           "Longest prefix match local multiple",
			addr:           "192.168.0.1",
			vpnRoutes:      []string{"192.168.0.0/16", "192.168.0.0/25", "192.168.0.0/27"},
			localRoutes:    []string{"192.168.0.0/24", "192.168.0.0/26", "192.168.0.0/28"},
			expectedVpn:    false,
			expectedPrefix: netip.MustParsePrefix("192.168.0.0/28"),
		},
		{
			name:           "Longest prefix match vpn",
			addr:           "192.168.1.1",
			vpnRoutes:      []string{"192.168.1.0/24"},
			localRoutes:    []string{"192.168.0.0/16"},
			expectedVpn:    true,
			expectedPrefix: netip.MustParsePrefix("192.168.1.0/24"),
		},
		{
			name:           "Longest prefix match vpn multiple",
			addr:           "192.168.0.1",
			vpnRoutes:      []string{"192.168.0.0/16", "192.168.0.0/25", "192.168.0.0/27"},
			localRoutes:    []string{"192.168.0.0/24", "192.168.0.0/26"},
			expectedVpn:    true,
			expectedPrefix: netip.MustParsePrefix("192.168.0.0/27"),
		},
		{
			name:           "Duplicate prefix in both",
			addr:           "192.168.1.1",
			vpnRoutes:      []string{"192.168.1.0/24"},
			localRoutes:    []string{"192.168.1.0/24"},
			expectedVpn:    false,
			expectedPrefix: netip.MustParsePrefix("192.168.1.0/24"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := netip.ParseAddr(tt.addr)
			if err != nil {
				t.Fatalf("Failed to parse address %s: %v", tt.addr, err)
			}

			var vpnRoutes, localRoutes []netip.Prefix
			for _, route := range tt.vpnRoutes {
				prefix, err := netip.ParsePrefix(route)
				if err != nil {
					t.Fatalf("Failed to parse VPN route %s: %v", route, err)
				}
				vpnRoutes = append(vpnRoutes, prefix)
			}

			for _, route := range tt.localRoutes {
				prefix, err := netip.ParsePrefix(route)
				if err != nil {
					t.Fatalf("Failed to parse local route %s: %v", route, err)
				}
				localRoutes = append(localRoutes, prefix)
			}

			isVpn, matchedPrefix := isVpnRoute(addr, vpnRoutes, localRoutes)
			assert.Equal(t, tt.expectedVpn, isVpn, "isVpnRoute should return expectedVpn value")
			assert.Equal(t, tt.expectedPrefix, matchedPrefix, "isVpnRoute should return expectedVpn prefix")
		})
	}
}
