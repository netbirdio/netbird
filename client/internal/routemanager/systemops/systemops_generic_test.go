//go:build !android && !ios

package systemops

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"syscall"
	"testing"

	"github.com/pion/transport/v3/stdnet"
	log "github.com/sirupsen/logrus"
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

func TestAddRemoveRoutes(t *testing.T) {
	testCases := []struct {
		name                   string
		prefix                 netip.Prefix
		shouldRouteToWireguard bool
		shouldBeRemoved        bool
	}{
		{
			name:                   "Should Add And Remove Route 100.66.120.0/24",
			prefix:                 netip.MustParsePrefix("100.66.120.0/24"),
			shouldRouteToWireguard: true,
			shouldBeRemoved:        true,
		},
		{
			name:                   "Should Not Add Or Remove Route 127.0.0.1/32",
			prefix:                 netip.MustParsePrefix("127.0.0.1/32"),
			shouldRouteToWireguard: false,
			shouldBeRemoved:        false,
		},
	}

	for n, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("NB_DISABLE_ROUTE_CACHE", "true")

			peerPrivateKey, _ := wgtypes.GeneratePrivateKey()
			newNet, err := stdnet.NewNet()
			if err != nil {
				t.Fatal(err)
			}
			opts := iface.WGIFaceOpts{
				IFaceName:    fmt.Sprintf("utun53%d", n),
				Address:      "100.65.75.2/24",
				WGPrivKey:    peerPrivateKey.String(),
				MTU:          iface.DefaultMTU,
				TransportNet: newNet,
			}
			wgInterface, err := iface.NewWGIFace(opts)
			require.NoError(t, err, "should create testing WGIface interface")
			defer wgInterface.Close()

			err = wgInterface.Create()
			require.NoError(t, err, "should create testing wireguard interface")

			r := NewSysOps(wgInterface, nil)

			_, _, err = r.SetupRouting(nil, nil)
			require.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, r.CleanupRouting(nil))
			})

			index, err := net.InterfaceByName(wgInterface.Name())
			require.NoError(t, err, "InterfaceByName should not return err")
			intf := &net.Interface{Index: index.Index, Name: wgInterface.Name()}

			if err = r.AddVPNRoute(testCase.prefix, intf); err != nil && !errors.Is(err, vars.ErrRouteNotAllowed) {
				t.Fatalf("AddVPNRoute should not return err: %v", err)
			}

			if testCase.shouldRouteToWireguard {
				assertWGOutInterface(t, testCase.prefix, wgInterface, false)
			} else {
				assertWGOutInterface(t, testCase.prefix, wgInterface, true)
			}
			exists, err := existsInRouteTable(testCase.prefix)
			require.NoError(t, err, "existsInRouteTable should not return err")
			if exists && testCase.shouldRouteToWireguard {
				err = r.RemoveVPNRoute(testCase.prefix, intf)
				require.NoError(t, err, "genericRemoveVPNRoute should not return err")

				prefixNexthop, err := GetNextHop(testCase.prefix.Addr())
				require.NoError(t, err, "GetNextHop should not return err")

				internetNexthop, err := GetNextHop(netip.MustParseAddr("0.0.0.0"))
				require.NoError(t, err)

				if testCase.shouldBeRemoved {
					require.Equal(t, internetNexthop.IP, prefixNexthop.IP, "route should be pointing to default internet gateway")
				} else {
					require.NotEqual(t, internetNexthop.IP, prefixNexthop.IP, "route should be pointing to a different gateway than the internet gateway")
				}
			}
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

func TestAddExistAndRemoveRoute(t *testing.T) {
	defaultNexthop, err := GetNextHop(netip.MustParseAddr("0.0.0.0"))
	t.Log("defaultNexthop: ", defaultNexthop)
	require.NoError(t, err, "shouldn't return error when fetching the gateway")

	testCases := []struct {
		name              string
		prefix            netip.Prefix
		preExistingPrefix netip.Prefix
		shouldAddRoute    bool
		expectError       bool
	}{
		{
			name:           "Should Add And Remove random Route",
			prefix:         netip.MustParsePrefix("99.99.99.99/32"),
			shouldAddRoute: true,
		},
		{
			name:              "Should Add Route if bigger network exists",
			prefix:            netip.MustParsePrefix("100.100.100.0/24"),
			preExistingPrefix: netip.MustParsePrefix("100.100.0.0/16"),
			shouldAddRoute:    true,
		},
		{
			name:              "Should Add Route if smaller network exists",
			prefix:            netip.MustParsePrefix("100.100.0.0/16"),
			preExistingPrefix: netip.MustParsePrefix("100.100.100.0/24"),
			shouldAddRoute:    true,
		},
		{
			name:              "Should Error on duplicate route",
			prefix:            netip.MustParsePrefix("100.100.0.0/16"),
			preExistingPrefix: netip.MustParsePrefix("100.100.0.0/16"),
			expectError:       true,
		},
	}

	for n, testCase := range testCases {
		log.SetLevel(log.TraceLevel)
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("NB_USE_LEGACY_ROUTING", "true")
			t.Setenv("NB_DISABLE_ROUTE_CACHE", "true")

			peerPrivateKey, _ := wgtypes.GeneratePrivateKey()
			newNet, err := stdnet.NewNet()
			require.NoError(t, err, "should create new net")

			opts := iface.WGIFaceOpts{
				IFaceName:    fmt.Sprintf("utun53%d", n),
				Address:      "100.65.75.2/24",
				WGPort:       33100,
				WGPrivKey:    peerPrivateKey.String(),
				MTU:          iface.DefaultMTU,
				TransportNet: newNet,
			}
			wgInterface, err := iface.NewWGIFace(opts)
			require.NoError(t, err, "should create testing WGIface interface")
			defer wgInterface.Close()

			err = wgInterface.Create()
			require.NoError(t, err, "should create testing wireguard interface")

			index, err := net.InterfaceByName(wgInterface.Name())
			require.NoError(t, err, "InterfaceByName should not return err")
			intf := &net.Interface{Index: index.Index, Name: wgInterface.Name()}

			r := NewSysOps(wgInterface, nil)

			// Prepare the environment
			if testCase.preExistingPrefix.IsValid() {
				err := r.AddVPNRoute(testCase.preExistingPrefix, intf)
				require.NoError(t, err, "should not return err when adding pre-existing route")
			}

			// Add the route
			err = r.AddVPNRoute(testCase.prefix, intf)

			if testCase.expectError {
				require.Error(t, err, "should return error")
				return
			}

			require.NoError(t, err, "should not return err when adding route")

			if testCase.shouldAddRoute {
				// test if route exists after adding
				ok, err := existsInRouteTable(testCase.prefix)
				require.NoError(t, err, "should not return err")
				require.True(t, ok, "route should exist")

				// remove route again if added
				err = r.RemoveVPNRoute(testCase.prefix, intf)
				require.NoError(t, err, "should not return err")

				// route should be removed
				ok, err = existsInRouteTable(testCase.prefix)
				require.NoError(t, err, "should not return err")
				require.False(t, ok, "route should not exist after removal")
			}
		})
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

func assertWGOutInterface(t *testing.T, prefix netip.Prefix, iface *iface.WGIface, invert bool) {
	t.Helper()
	if runtime.GOOS == "linux" && prefix.Addr().IsLoopback() {
		return
	}

	prefixNexthop, err := GetNextHop(prefix.Addr())
	require.NoError(t, err, "GetNextHop should not return err")
	if invert {
		assert.NotEqual(t, iface.Address().IP.String(), prefixNexthop.IP.String(), "route should not point to wireguard interface IP")
	} else {
		assert.Equal(t, iface.Name(), prefixNexthop.Intf.Name, "route should point to wireguard interface")
	}
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

