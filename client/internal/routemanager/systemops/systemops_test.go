package systemops

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/routemanager/notifier"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
)

type mockWGIface struct {
	address wgaddr.Address
	name    string
}

func (m *mockWGIface) Address() wgaddr.Address {
	return m.address
}

func (m *mockWGIface) Name() string {
	return m.name
}

func TestSysOps_validateRoute(t *testing.T) {
	wgNetwork := netip.MustParsePrefix("10.0.0.0/24")
	mockWG := &mockWGIface{
		address: wgaddr.Address{
			IP:      wgNetwork.Addr(),
			Network: wgNetwork,
		},
		name: "wg0",
	}

	sysOps := &SysOps{
		wgInterface: mockWG,
		notifier:    &notifier.Notifier{},
	}

	tests := []struct {
		name        string
		prefix      string
		expectError bool
	}{
		// Valid routes
		{
			name:        "valid IPv4 route",
			prefix:      "192.168.1.0/24",
			expectError: false,
		},
		{
			name:        "valid IPv6 route",
			prefix:      "2001:db8::/32",
			expectError: false,
		},
		{
			name:        "valid single IPv4 host",
			prefix:      "8.8.8.8/32",
			expectError: false,
		},
		{
			name:        "valid single IPv6 host",
			prefix:      "2001:4860:4860::8888/128",
			expectError: false,
		},

		// Invalid routes - loopback
		{
			name:        "IPv4 loopback",
			prefix:      "127.0.0.1/32",
			expectError: true,
		},
		{
			name:        "IPv6 loopback",
			prefix:      "::1/128",
			expectError: true,
		},

		// Invalid routes - link-local unicast
		{
			name:        "IPv4 link-local unicast",
			prefix:      "169.254.1.1/32",
			expectError: true,
		},
		{
			name:        "IPv6 link-local unicast",
			prefix:      "fe80::1/128",
			expectError: true,
		},

		// Invalid routes - multicast
		{
			name:        "IPv4 multicast",
			prefix:      "224.0.0.1/32",
			expectError: true,
		},
		{
			name:        "IPv6 multicast",
			prefix:      "ff02::1/128",
			expectError: true,
		},

		// Invalid routes - link-local multicast
		{
			name:        "IPv4 link-local multicast",
			prefix:      "224.0.0.0/24",
			expectError: true,
		},
		{
			name:        "IPv6 link-local multicast",
			prefix:      "ff02::/16",
			expectError: true,
		},

		// Invalid routes - interface-local multicast (IPv6 only)
		{
			name:        "IPv6 interface-local multicast",
			prefix:      "ff01::1/128",
			expectError: true,
		},

		// Invalid routes - overlaps with WG interface network
		{
			name:        "overlaps with WG network - exact match",
			prefix:      "10.0.0.0/24",
			expectError: true,
		},
		{
			name:        "overlaps with WG network - subset",
			prefix:      "10.0.0.1/32",
			expectError: true,
		},
		{
			name:        "overlaps with WG network - host in range",
			prefix:      "10.0.0.100/32",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, err := netip.ParsePrefix(tt.prefix)
			require.NoError(t, err, "Failed to parse test prefix %s", tt.prefix)

			err = sysOps.validateRoute(prefix)

			if tt.expectError {
				require.Error(t, err, "validateRoute() expected error for %s", tt.prefix)
				assert.Equal(t, vars.ErrRouteNotAllowed, err, "validateRoute() expected ErrRouteNotAllowed for %s", tt.prefix)
			} else {
				assert.NoError(t, err, "validateRoute() expected no error for %s", tt.prefix)
			}
		})
	}
}

func TestSysOps_validateRoute_SubnetOverlap(t *testing.T) {
	wgNetwork := netip.MustParsePrefix("192.168.100.0/24")
	mockWG := &mockWGIface{
		address: wgaddr.Address{
			IP:      wgNetwork.Addr(),
			Network: wgNetwork,
		},
		name: "wg0",
	}

	sysOps := &SysOps{
		wgInterface: mockWG,
		notifier:    &notifier.Notifier{},
	}

	tests := []struct {
		name        string
		prefix      string
		expectError bool
		description string
	}{
		{
			name:        "identical subnet",
			prefix:      "192.168.100.0/24",
			expectError: true,
			description: "exact same network as WG interface",
		},
		{
			name:        "broader subnet containing WG network",
			prefix:      "192.168.0.0/16",
			expectError: false,
			description: "broader network that contains WG network should be allowed",
		},
		{
			name:        "host within WG network",
			prefix:      "192.168.100.50/32",
			expectError: true,
			description: "specific host within WG network",
		},
		{
			name:        "subnet within WG network",
			prefix:      "192.168.100.128/25",
			expectError: true,
			description: "smaller subnet within WG network",
		},
		{
			name:        "adjacent subnet - same /23",
			prefix:      "192.168.101.0/24",
			expectError: false,
			description: "adjacent subnet, no overlap",
		},
		{
			name:        "adjacent subnet - different /16",
			prefix:      "192.167.100.0/24",
			expectError: false,
			description: "different network, no overlap",
		},
		{
			name:        "WG network broadcast address",
			prefix:      "192.168.100.255/32",
			expectError: true,
			description: "broadcast address of WG network",
		},
		{
			name:        "WG network first usable",
			prefix:      "192.168.100.1/32",
			expectError: true,
			description: "first usable address in WG network",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, err := netip.ParsePrefix(tt.prefix)
			require.NoError(t, err, "Failed to parse test prefix %s", tt.prefix)

			err = sysOps.validateRoute(prefix)

			if tt.expectError {
				require.Error(t, err, "validateRoute() expected error for %s (%s)", tt.prefix, tt.description)
				assert.Equal(t, vars.ErrRouteNotAllowed, err, "validateRoute() expected ErrRouteNotAllowed for %s (%s)", tt.prefix, tt.description)
			} else {
				assert.NoError(t, err, "validateRoute() expected no error for %s (%s)", tt.prefix, tt.description)
			}
		})
	}
}

func TestSysOps_validateRoute_InvalidPrefix(t *testing.T) {
	wgNetwork := netip.MustParsePrefix("10.0.0.0/24")
	mockWG := &mockWGIface{
		address: wgaddr.Address{
			IP:      wgNetwork.Addr(),
			Network: wgNetwork,
		},
		name: "nb0",
	}

	sysOps := &SysOps{
		wgInterface: mockWG,
		notifier:    &notifier.Notifier{},
	}

	var invalidPrefix netip.Prefix
	err := sysOps.validateRoute(invalidPrefix)

	require.Error(t, err, "validateRoute() expected error for invalid prefix")
	assert.Equal(t, vars.ErrRouteNotAllowed, err, "validateRoute() expected ErrRouteNotAllowed for invalid prefix")
}
