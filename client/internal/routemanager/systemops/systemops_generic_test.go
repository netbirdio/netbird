//go:build !android && !ios

package systemops

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"testing"

	"github.com/pion/transport/v3/stdnet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
)

type dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func TestAddVPNRoute(t *testing.T) {
	testCases := []struct {
		name        string
		prefix      netip.Prefix
		expectError bool
	}{
		{
			name:   "IPv4 - Private network route",
			prefix: netip.MustParsePrefix("10.10.100.0/24"),
		},
		{
			name:   "IPv4 Single host",
			prefix: netip.MustParsePrefix("8.8.8.8/32"),
		},
		{
			name:   "IPv4 RFC3927 test range",
			prefix: netip.MustParsePrefix("198.51.100.0/24"),
		},

		{
			name:   "IPv6 Subnet",
			prefix: netip.MustParsePrefix("2001:db8:1000::/48"),
		},
		{
			name:   "IPv6 Single host",
			prefix: netip.MustParsePrefix("2001:db8::1/128"),
		},

		// IPv4 addresses that should be rejected (matches validateRoute logic)
		{
			name:        "IPv4 Loopback",
			prefix:      netip.MustParsePrefix("127.0.0.1/32"),
			expectError: true,
		},
		{
			name:        "IPv4 Link-local unicast",
			prefix:      netip.MustParsePrefix("169.254.1.1/32"),
			expectError: true,
		},
		{
			name:        "IPv4 Link-local multicast",
			prefix:      netip.MustParsePrefix("224.0.0.251/32"),
			expectError: true,
		},
		{
			name:        "IPv4 Multicast",
			prefix:      netip.MustParsePrefix("239.255.255.250/32"),
			expectError: true,
		},
		{
			name:        "IPv4 Unspecified with prefix",
			prefix:      netip.MustParsePrefix("0.0.0.0/32"),
			expectError: true,
		},

		// IPv6 addresses that should be rejected (matches validateRoute logic)
		{
			name:        "IPv6 Loopback",
			prefix:      netip.MustParsePrefix("::1/128"),
			expectError: true,
		},
		{
			name:        "IPv6 Link-local unicast",
			prefix:      netip.MustParsePrefix("fe80::1/128"),
			expectError: true,
		},
		{
			name:        "IPv6 Link-local multicast",
			prefix:      netip.MustParsePrefix("ff02::1/128"),
			expectError: true,
		},
		{
			name:        "IPv6 Interface-local multicast",
			prefix:      netip.MustParsePrefix("ff01::1/128"),
			expectError: true,
		},
		{
			name:        "IPv6 Multicast",
			prefix:      netip.MustParsePrefix("ff00::1/128"),
			expectError: true,
		},
		{
			name:        "IPv6 Unspecified with prefix",
			prefix:      netip.MustParsePrefix("::/128"),
			expectError: true,
		},

		{
			name:        "IPv4 WireGuard interface network overlap",
			prefix:      netip.MustParsePrefix("100.65.75.0/24"),
			expectError: true,
		},
		{
			name:        "IPv4 WireGuard interface network subnet",
			prefix:      netip.MustParsePrefix("100.65.75.0/32"),
			expectError: true,
		},


	}

	for n, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("NB_DISABLE_ROUTE_CACHE", "true")

			wgInterface := createWGInterface(t, fmt.Sprintf("utun53%d", n), "100.65.75.2/24", 33100+n)

			r := NewSysOps(wgInterface, nil)
			_, _, err := r.SetupRouting(nil, nil)
			require.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, r.CleanupRouting(nil))
			})

			intf, err := net.InterfaceByName(wgInterface.Name())
			require.NoError(t, err)

			// add the route
			err = r.AddVPNRoute(testCase.prefix, intf)
			if testCase.expectError {
				assert.ErrorIs(t, err, vars.ErrRouteNotAllowed,
					"Error should be ErrRouteNotAllowed, got: %v", err)
				return
			}

			// validate it's pointing to the WireGuard interface
			require.NoError(t, err)
			nextHop, err := GetNextHop(testCase.prefix.Addr())
			require.NoError(t, err)
			assert.Equal(t, wgInterface.Name(), nextHop.Intf.Name, "next hop interface should be WireGuard interface")

			// remove route again
			err = r.RemoveVPNRoute(testCase.prefix, intf)
			require.NoError(t, err, "RemoveVPNRoute should not return err")

			// validate it's gone
			nextHop, err = GetNextHop(testCase.prefix.Addr())
			require.NoError(t, err)
			assert.NotNil(t, nextHop.Intf)
			assert.NotEqual(t, nextHop.Intf.Name, wgInterface.Name())
		})
	}
}

func TestGetNextHop(t *testing.T) {
	defaultNh, err := GetNextHop(netip.MustParseAddr("0.0.0.0"))
	if err != nil {
		t.Fatal("shouldn't return error when fetching the gateway: ", err)
	}
	if !defaultNh.IP.IsValid() {
		t.Fatal("should return a gateway")
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal("shouldn't return error when fetching interface addresses: ", err)
	}

	var testingPrefix netip.Prefix
	for _, address := range addresses {
		if address.Network() != "ip+net" {
			continue
		}
		prefix := netip.MustParsePrefix(address.String())
		if !prefix.Addr().IsLoopback() && prefix.Addr().Is4() {
			testingPrefix = prefix.Masked()
			break
		}
	}

	nh, err := GetNextHop(testingPrefix.Addr())
	if err != nil {
		t.Fatal("shouldn't return error: ", err)
	}
	if nh.Intf == nil {
		t.Fatal("should return a gateway for local network")
	}
	if nh.IP.String() == defaultNh.IP.String() {
		t.Fatal("next hop IP should not match with default gateway IP")
	}
	if nh.Intf.Name != defaultNh.Intf.Name {
		t.Fatalf("next hop interface name should match with default gateway interface name, got: %s, want: %s", nh.Intf.Name, defaultNh.Intf.Name)
	}
}

func createWGInterface(t *testing.T, interfaceName, ipAddressCIDR string, listenPort int) *iface.WGIface {
	t.Helper()

	peerPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	newNet, err := stdnet.NewNet()
	require.NoError(t, err)

	opts := iface.WGIFaceOpts{
		IFaceName:    interfaceName,
		Address:      ipAddressCIDR,
		WGPrivKey:    peerPrivateKey.String(),
		WGPort:       listenPort,
		MTU:          iface.DefaultMTU,
		TransportNet: newNet,
	}
	wgInterface, err := iface.NewWGIFace(opts)
	require.NoError(t, err, "should create testing WireGuard interface")

	err = wgInterface.Create()
	require.NoError(t, err, "should create testing WireGuard interface")

	t.Cleanup(func() {
		wgInterface.Close()
	})

	return wgInterface
}

func setupRouteAndCleanup(t *testing.T, r *SysOps, prefix netip.Prefix, intf *net.Interface) {
	t.Helper()

	if err := r.AddVPNRoute(prefix, intf); err != nil {
		if !errors.Is(err, syscall.EEXIST) && !errors.Is(err, vars.ErrRouteNotAllowed) {
			t.Fatalf("addVPNRoute should not return err: %v", err)
		}
		t.Logf("addVPNRoute %v returned: %v", prefix, err)
	}
	t.Cleanup(func() {
		if err := r.RemoveVPNRoute(prefix, intf); err != nil && !errors.Is(err, vars.ErrRouteNotAllowed) {
			t.Fatalf("removeVPNRoute should not return err: %v", err)
		}
	})
}

func setupTestEnv(t *testing.T) {
	t.Helper()

	setupDummyInterfacesAndRoutes(t)

	wgInterface := createWGInterface(t, expectedVPNint, "100.64.0.1/24", 51820)
	t.Cleanup(func() {
		assert.NoError(t, wgInterface.Close())
	})

	r := NewSysOps(wgInterface, nil)
	_, _, err := r.SetupRouting(nil, nil)
	require.NoError(t, err, "setupRouting should not return err")
	t.Cleanup(func() {
		assert.NoError(t, r.CleanupRouting(nil))
	})

	index, err := net.InterfaceByName(wgInterface.Name())
	require.NoError(t, err, "InterfaceByName should not return err")
	intf := &net.Interface{Index: index.Index, Name: wgInterface.Name()}

	// default route exists in main table and vpn table
	setupRouteAndCleanup(t, r, netip.MustParsePrefix("0.0.0.0/0"), intf)

	// 10.0.0.0/8 route exists in main table and vpn table
	setupRouteAndCleanup(t, r, netip.MustParsePrefix("10.0.0.0/8"), intf)

	// 10.10.0.0/24 more specific route exists in vpn table
	setupRouteAndCleanup(t, r, netip.MustParsePrefix("10.10.0.0/24"), intf)

	// unique route in vpn table
	setupRouteAndCleanup(t, r, netip.MustParsePrefix("172.16.0.0/12"), intf)
}

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

func existsInRouteTable(prefix netip.Prefix) (bool, error) {
	routes, err := GetRoutesFromTable()
	if err != nil {
		return false, fmt.Errorf("get routes from table: %w", err)
	}
	for _, tableRoute := range routes {
		if tableRoute == prefix {
			return true, nil
		}
	}
	return false, nil
}
