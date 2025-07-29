//go:build !android && !ios

package systemops

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/pion/transport/v3/stdnet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/internal/routemanager/vars"
	nbnet "github.com/netbirdio/netbird/client/net"
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
			prefix: netip.MustParsePrefix("10.111.111.111/32"),
		},
		{
			name:   "IPv4 RFC3927 test range",
			prefix: netip.MustParsePrefix("198.51.100.0/24"),
		},
		{
			name:   "IPv4 Default route",
			prefix: netip.MustParsePrefix("0.0.0.0/0"),
		},

		{
			name:   "IPv6 Subnet",
			prefix: netip.MustParsePrefix("fdb1:848a:7e16::/48"),
		},
		{
			name:   "IPv6 Single host",
			prefix: netip.MustParsePrefix("fdb1:848a:7e16:a::b/128"),
		},
		{
			name:   "IPv6 Default route",
			prefix: netip.MustParsePrefix("::/0"),
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
			advancedRouting := nbnet.AdvancedRouting()
			err := r.SetupRouting(nil, nil, advancedRouting)
			require.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, r.CleanupRouting(nil, advancedRouting))
			})

			intf, err := net.InterfaceByName(wgInterface.Name())
			require.NoError(t, err)

			// add the route
			err = r.AddVPNRoute(testCase.prefix, intf)
			if testCase.expectError {
				assert.ErrorIs(t, err, vars.ErrRouteNotAllowed)
				return
			}

			// validate it's pointing to the WireGuard interface
			require.NoError(t, err)

			nextHop := getNextHop(t, testCase.prefix.Addr())
			assert.Equal(t, wgInterface.Name(), nextHop.Intf.Name, "next hop interface should be WireGuard interface")

			// remove route again
			err = r.RemoveVPNRoute(testCase.prefix, intf)
			require.NoError(t, err)

			// validate it's gone
			nextHop, err = GetNextHop(testCase.prefix.Addr())
			require.True(t,
				errors.Is(err, vars.ErrRouteNotFound) || err == nil && nextHop.Intf != nil && nextHop.Intf.Name != wgInterface.Name(),
				"err: %v, next hop: %v", err, nextHop)
		})
	}
}

func getNextHop(t *testing.T, addr netip.Addr) Nexthop {
	t.Helper()

	if runtime.GOOS == "windows" || runtime.GOOS == "linux" {
		nextHop, err := GetNextHop(addr)

		if runtime.GOOS == "windows" && errors.Is(err, vars.ErrRouteNotFound) && addr.Is6() {
			// TODO: Fix this test. It doesn't return the route when running in a windows github runner, but it is
			// present in the route table.
			t.Skip("Skipping windows test")
		}

		require.NoError(t, err)
		require.NotNil(t, nextHop.Intf, "next hop interface should not be nil for %s", addr)

		return nextHop
	}
	// GetNextHop for bsd is buggy and returns the wrong interface for the default route.

	if addr.IsUnspecified() {
		// On macOS, querying 0.0.0.0 returns the wrong interface
		if addr.Is4() {
			addr = netip.MustParseAddr("1.2.3.4")
		} else {
			addr = netip.MustParseAddr("2001:db8::1")
		}
	}

	cmd := exec.Command("route", "-n", "get", addr.String())
	if addr.Is6() {
		cmd = exec.Command("route", "-n", "get", "-inet6", addr.String())
	}

	output, err := cmd.CombinedOutput()
	t.Logf("route output: %s", output)
	require.NoError(t, err, "%s failed")

	lines := strings.Split(string(output), "\n")
	var intf string
	var gateway string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			intf = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		} else if strings.HasPrefix(line, "gateway:") {
			gateway = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
	}

	require.NotEmpty(t, intf, "interface should be found in route output")

	iface, err := net.InterfaceByName(intf)
	require.NoError(t, err, "interface %s should exist", intf)

	nexthop := Nexthop{Intf: iface}

	if gateway != "" && gateway != "link#"+strconv.Itoa(iface.Index) {
		addr, err := netip.ParseAddr(gateway)
		if err == nil {
			nexthop.IP = addr
		}
	}

	return nexthop
}

func TestAddRouteToNonVPNIntf(t *testing.T) {
	testCases := []struct {
		name        string
		prefix      netip.Prefix
		expectError bool
		errorType   error
	}{
		{
			name:   "IPv4 RFC3927 test range",
			prefix: netip.MustParsePrefix("198.51.100.0/24"),
		},
		{
			name:   "IPv4 Single host",
			prefix: netip.MustParsePrefix("8.8.8.8/32"),
		},
		{
			name:   "IPv6 External network route",
			prefix: netip.MustParsePrefix("2001:db8:1000::/48"),
		},
		{
			name:   "IPv6 Single host",
			prefix: netip.MustParsePrefix("2001:db8::1/128"),
		},
		{
			name:   "IPv6 Subnet",
			prefix: netip.MustParsePrefix("2a05:d014:1f8d::/48"),
		},
		{
			name:   "IPv6 Single host",
			prefix: netip.MustParsePrefix("2a05:d014:1f8d:7302:ebca:ec15:b24d:d07e/128"),
		},

		// Addresses that should be rejected
		{
			name:        "IPv4 Loopback",
			prefix:      netip.MustParsePrefix("127.0.0.1/32"),
			expectError: true,
			errorType:   vars.ErrRouteNotAllowed,
		},
		{
			name:        "IPv4 Link-local unicast",
			prefix:      netip.MustParsePrefix("169.254.1.1/32"),
			expectError: true,
			errorType:   vars.ErrRouteNotAllowed,
		},
		{
			name:        "IPv4 Multicast",
			prefix:      netip.MustParsePrefix("239.255.255.250/32"),
			expectError: true,
			errorType:   vars.ErrRouteNotAllowed,
		},
		{
			name:        "IPv4 Unspecified",
			prefix:      netip.MustParsePrefix("0.0.0.0/0"),
			expectError: true,
			errorType:   vars.ErrRouteNotAllowed,
		},
		{
			name:        "IPv6 Loopback",
			prefix:      netip.MustParsePrefix("::1/128"),
			expectError: true,
			errorType:   vars.ErrRouteNotAllowed,
		},
		{
			name:        "IPv6 Link-local unicast",
			prefix:      netip.MustParsePrefix("fe80::1/128"),
			expectError: true,
			errorType:   vars.ErrRouteNotAllowed,
		},
		{
			name:        "IPv6 Multicast",
			prefix:      netip.MustParsePrefix("ff00::1/128"),
			expectError: true,
			errorType:   vars.ErrRouteNotAllowed,
		},
		{
			name:        "IPv6 Unspecified",
			prefix:      netip.MustParsePrefix("::/0"),
			expectError: true,
			errorType:   vars.ErrRouteNotAllowed,
		},
		{
			name:        "IPv4 WireGuard interface network overlap",
			prefix:      netip.MustParsePrefix("100.65.75.0/24"),
			expectError: true,
			errorType:   vars.ErrRouteNotAllowed,
		},
	}

	for n, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("NB_DISABLE_ROUTE_CACHE", "true")

			wgInterface := createWGInterface(t, fmt.Sprintf("utun54%d", n), "100.65.75.2/24", 33200+n)

			r := NewSysOps(wgInterface, nil)
			advancedRouting := nbnet.AdvancedRouting()
			err := r.SetupRouting(nil, nil, advancedRouting)
			require.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, r.CleanupRouting(nil, advancedRouting))
			})

			initialNextHopV4, err := GetNextHop(netip.IPv4Unspecified())
			require.NoError(t, err, "Should be able to get IPv4 default route")
			t.Logf("Initial IPv4 next hop: %s", initialNextHopV4)

			initialNextHopV6, err := GetNextHop(netip.IPv6Unspecified())
			if testCase.prefix.Addr().Is6() &&
				(errors.Is(err, vars.ErrRouteNotFound) || initialNextHopV6.Intf != nil && strings.HasPrefix(initialNextHopV6.Intf.Name, "utun")) {
				t.Skip("Skipping test as no ipv6 default route is available")
			}
			if err != nil && !errors.Is(err, vars.ErrRouteNotFound) {
				t.Fatalf("Failed to get IPv6 default route: %v", err)
			}

			var initialNextHop Nexthop
			if testCase.prefix.Addr().Is6() {
				initialNextHop = initialNextHopV6
			} else {
				initialNextHop = initialNextHopV4
			}

			nexthop, err := r.addRouteToNonVPNIntf(testCase.prefix, wgInterface, initialNextHop)

			if testCase.expectError {
				require.ErrorIs(t, err, vars.ErrRouteNotAllowed)
				return
			}
			require.NoError(t, err)
			t.Logf("Next hop for %s: %s", testCase.prefix, nexthop)

			// Verify the route was added and points to non-VPN interface
			currentNextHop, err := GetNextHop(testCase.prefix.Addr())
			require.NoError(t, err)
			assert.NotEqual(t, wgInterface.Name(), currentNextHop.Intf.Name, "Route should not point to VPN interface")

			err = r.removeFromRouteTable(testCase.prefix, nexthop)
			assert.NoError(t, err)
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
	advancedRouting := nbnet.AdvancedRouting()
	err := r.SetupRouting(nil, nil, advancedRouting)
	require.NoError(t, err, "setupRouting should not return err")
	t.Cleanup(func() {
		assert.NoError(t, r.CleanupRouting(nil, advancedRouting))
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
