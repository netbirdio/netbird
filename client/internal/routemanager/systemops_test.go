//go:build !android && !ios

package routemanager

import (
	"bytes"
	"context"
	"fmt"
	"github.com/google/gopacket/routing"
	"github.com/netbirdio/netbird/client/firewall"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/pion/transport/v3/stdnet"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/iface"
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
		{
			name:                   "Should Add And Remove Route 2001:db8:1234:5678::/64",
			prefix:                 netip.MustParsePrefix("2001:db8:1234:5678::/64"),
			shouldRouteToWireguard: true,
			shouldBeRemoved:        true,
		},
		{
			name:                   "Should Not Add Or Remove Route ::1/128",
			prefix:                 netip.MustParsePrefix("::1/128"),
			shouldRouteToWireguard: false,
			shouldBeRemoved:        false,
		},
	}

	for n, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("NB_DISABLE_ROUTE_CACHE", "true")

			v6Addr := ""
			hasV6DefaultRoute, err := EnvironmentHasIPv6DefaultRoute()
			//goland:noinspection GoBoolExpressions
			if (!iface.SupportsIPv6() || !firewall.SupportsIPv6() || !hasV6DefaultRoute || err != nil) && testCase.prefix.Addr().Is6() {
				t.Skip("Platform does not support IPv6, skipping IPv6 test...")
			} else if testCase.prefix.Addr().Is6() {
				v6Addr = "2001:db8::4242:4711/128"
			}

			peerPrivateKey, _ := wgtypes.GeneratePrivateKey()
			newNet, err := stdnet.NewNet()
			if err != nil {
				t.Fatal(err)
			}
			wgInterface, err := iface.NewWGIFace(fmt.Sprintf("utun53%d", n), "100.65.75.2/24", v6Addr, 33100, peerPrivateKey.String(), iface.DefaultMTU, newNet, nil)
			require.NoError(t, err, "should create testing WGIface interface")
			defer wgInterface.Close()

			err = wgInterface.Create()
			require.NoError(t, err, "should create testing wireguard interface")
			_, _, err = setupRouting(nil, wgInterface)
			require.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, cleanupRouting())
			})

			index, err := net.InterfaceByName(wgInterface.Name())
			require.NoError(t, err, "InterfaceByName should not return err")
			intf := &net.Interface{Index: index.Index, Name: wgInterface.Name()}

			err = addVPNRoute(testCase.prefix, intf)
			require.NoError(t, err, "genericAddVPNRoute should not return err")

			if testCase.shouldRouteToWireguard {
				assertWGOutInterface(t, testCase.prefix, wgInterface, false)
			} else {
				assertWGOutInterface(t, testCase.prefix, wgInterface, true)
			}
			exists, err := existsInRouteTable(testCase.prefix)
			require.NoError(t, err, "existsInRouteTable should not return err")
			if exists && testCase.shouldRouteToWireguard {
				err = removeVPNRoute(testCase.prefix, intf)
				require.NoError(t, err, "genericRemoveVPNRoute should not return err")

				prefixGateway, _, err := GetNextHop(testCase.prefix.Addr())
				require.NoError(t, err, "GetNextHop should not return err")

				internetGateway, _, err := GetNextHop(netip.MustParseAddr("0.0.0.0"))
				require.NoError(t, err)
				if testCase.prefix.Addr().Is6() {
					internetGateway, _, err = GetNextHop(netip.MustParseAddr("::/0"))
				}
				require.NoError(t, err)

				if testCase.shouldBeRemoved {
					require.Equal(t, internetGateway, prefixGateway, "route should be pointing to default internet gateway")
				} else {
					require.NotEqual(t, internetGateway, prefixGateway, "route should be pointing to a different gateway than the internet gateway")
				}
			}
		})
	}
}

func TestGetNextHop(t *testing.T) {
	gateway, _, err := GetNextHop(netip.MustParseAddr("0.0.0.0"))
	if err != nil {
		t.Fatal("shouldn't return error when fetching the gateway: ", err)
	}
	if !gateway.IsValid() {
		t.Fatal("should return a gateway")
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal("shouldn't return error when fetching interface addresses: ", err)
	}

	var testingIP string
	var testingPrefix netip.Prefix
	for _, address := range addresses {
		if address.Network() != "ip+net" {
			continue
		}
		prefix := netip.MustParsePrefix(address.String())
		if !prefix.Addr().IsLoopback() && prefix.Addr().Is4() {
			testingIP = prefix.Addr().String()
			testingPrefix = prefix.Masked()
			break
		}
	}

	localIP, _, err := GetNextHop(testingPrefix.Addr())
	if err != nil {
		t.Fatal("shouldn't return error: ", err)
	}
	if !localIP.IsValid() {
		t.Fatal("should return a gateway for local network")
	}
	if localIP.String() == gateway.String() {
		t.Fatal("local ip should not match with gateway IP")
	}
	if localIP.String() != testingIP {
		t.Fatalf("local ip should match with testing IP: want %s got %s", testingIP, localIP.String())
	}
}

func TestAddExistAndRemoveRoute(t *testing.T) {
	defaultGateway, _, err := GetNextHop(netip.MustParseAddr("0.0.0.0"))
	t.Log("defaultGateway: ", defaultGateway)
	if err != nil {
		t.Fatal("shouldn't return error when fetching the gateway: ", err)
	}
	var defaultGateway6 *netip.Addr
	hasV6DefaultRoute, err := EnvironmentHasIPv6DefaultRoute()
	//goland:noinspection GoBoolExpressions
	if iface.SupportsIPv6() && firewall.SupportsIPv6() && hasV6DefaultRoute && err == nil {
		gw6, _, err := GetNextHop(netip.MustParseAddr("::"))
		gw6 = gw6.WithZone("")
		defaultGateway6 = &gw6
		t.Log("defaultGateway6: ", defaultGateway6)
		if err != nil {
			t.Fatal("shouldn't return error when fetching the IPv6 gateway: ", err)
		}
	}
	testCases := []struct {
		name              string
		prefix            netip.Prefix
		preExistingPrefix netip.Prefix
		shouldAddRoute    bool
	}{
		{
			name:           "Should Add And Remove random Route",
			prefix:         netip.MustParsePrefix("99.99.99.99/32"),
			shouldAddRoute: true,
		},
		{
			name:           "Should Not Add Route if overlaps with default gateway",
			prefix:         netip.MustParsePrefix(defaultGateway.String() + "/31"),
			shouldAddRoute: false,
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
			name:              "Should Not Add Route if same network exists",
			prefix:            netip.MustParsePrefix("100.100.0.0/16"),
			preExistingPrefix: netip.MustParsePrefix("100.100.0.0/16"),
			shouldAddRoute:    false,
		},
		{
			name:           "Should Add And Remove random Route (IPv6)",
			prefix:         netip.MustParsePrefix("2001:db8::abcd/128"),
			shouldAddRoute: true,
		},
		{
			name:              "Should Add Route if bigger network exists (IPv6)",
			prefix:            netip.MustParsePrefix("2001:db8:b14d:abcd:1234::/96"),
			preExistingPrefix: netip.MustParsePrefix("2001:db8:b14d:abcd::/64"),
			shouldAddRoute:    true,
		},
		{
			name:              "Should Add Route if smaller network exists (IPv6)",
			prefix:            netip.MustParsePrefix("2001:db8:b14d::/48"),
			preExistingPrefix: netip.MustParsePrefix("2001:db8:b14d:abcd::/64"),
			shouldAddRoute:    true,
		},
		{
			name:              "Should Not Add Route if same network exists (IPv6)",
			prefix:            netip.MustParsePrefix("2001:db8:b14d:abcd::/64"),
			preExistingPrefix: netip.MustParsePrefix("2001:db8:b14d:abcd::/64"),
			shouldAddRoute:    false,
		},
	}
	if defaultGateway6 != nil {
		testCases = append(testCases, []struct {
			name              string
			prefix            netip.Prefix
			preExistingPrefix netip.Prefix
			shouldAddRoute    bool
		}{
			{
				name:           "Should Not Add Route if overlaps with default gateway (IPv6)",
				prefix:         netip.MustParsePrefix(defaultGateway6.String() + "/127"),
				shouldAddRoute: false,
			},
		}...)
	}

	for n, testCase := range testCases {

		var buf bytes.Buffer
		log.SetOutput(&buf)
		defer func() {
			log.SetOutput(os.Stderr)
		}()
		t.Run(testCase.name, func(t *testing.T) {
			t.Setenv("NB_USE_LEGACY_ROUTING", "true")
			t.Setenv("NB_DISABLE_ROUTE_CACHE", "true")

			v6Addr := ""
			if testCase.prefix.Addr().Is6() && defaultGateway6 == nil {
				t.Skip("Platform does not support IPv6, skipping IPv6 test...")
			} else if testCase.prefix.Addr().Is6() {
				v6Addr = "2001:db8::4242:4711/128"
			}

			peerPrivateKey, _ := wgtypes.GeneratePrivateKey()
			newNet, err := stdnet.NewNet()
			if err != nil {
				t.Fatal(err)
			}
			wgInterface, err := iface.NewWGIFace(fmt.Sprintf("utun53%d", n), "100.65.75.2/24", v6Addr, 33100, peerPrivateKey.String(), iface.DefaultMTU, newNet, nil)
			require.NoError(t, err, "should create testing WGIface interface")
			defer wgInterface.Close()

			err = wgInterface.Create()
			require.NoError(t, err, "should create testing wireguard interface")

			index, err := net.InterfaceByName(wgInterface.Name())
			require.NoError(t, err, "InterfaceByName should not return err")
			intf := &net.Interface{Index: index.Index, Name: wgInterface.Name()}

			// Prepare the environment
			if testCase.preExistingPrefix.IsValid() {
				err := addVPNRoute(testCase.preExistingPrefix, intf)
				require.NoError(t, err, "should not return err when adding pre-existing route")
			}

			// Add the route
			err = addVPNRoute(testCase.prefix, intf)
			require.NoError(t, err, "should not return err when adding route")

			if testCase.shouldAddRoute {
				// test if route exists after adding
				ok, err := existsInRouteTable(testCase.prefix)
				require.NoError(t, err, "should not return err")
				require.True(t, ok, "route should exist")

				// remove route again if added
				err = removeVPNRoute(testCase.prefix, intf)
				require.NoError(t, err, "should not return err")
			}

			// route should either not have been added or should have been removed
			// In case of already existing route, it should not have been added (but still exist)
			ok, err := existsInRouteTable(testCase.prefix)
			t.Log("Buffer string: ", buf.String())
			require.NoError(t, err, "should not return err")

			if !strings.Contains(buf.String(), "because it already exists") {
				require.False(t, ok, "route should not exist")
			}
		})
	}
}

func TestIsSubRange(t *testing.T) {
	// Note: This test may fail for IPv6 in some environments, where there actually exists another route that the
	// determined prefix is a sub-range of.
	hasV6DefaultRoute, err := EnvironmentHasIPv6DefaultRoute()
	shouldIncludeV6Routes := iface.SupportsIPv6() && firewall.SupportsIPv6() && hasV6DefaultRoute && err == nil

	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal("shouldn't return error when fetching interface addresses: ", err)
	}

	var subRangeAddressPrefixes []netip.Prefix
	var nonSubRangeAddressPrefixes []netip.Prefix
	for _, address := range addresses {
		p := netip.MustParsePrefix(address.String())
		if !p.Addr().IsLoopback() && (p.Addr().Is4() && p.Bits() < 32) || (p.Addr().Is6() && shouldIncludeV6Routes && p.Bits() < 128) {
			p2 := netip.PrefixFrom(p.Masked().Addr(), p.Bits()+1)
			subRangeAddressPrefixes = append(subRangeAddressPrefixes, p2)
			nonSubRangeAddressPrefixes = append(nonSubRangeAddressPrefixes, p.Masked())
		}
	}

	for _, prefix := range subRangeAddressPrefixes {
		isSubRangePrefix, err := isSubRange(prefix)
		if err != nil {
			t.Fatal("shouldn't return error when checking if address is sub-range: ", err)
		}
		if !isSubRangePrefix {
			t.Fatalf("address %s should be sub-range of an existing route in the table", prefix)
		}
	}

	for _, prefix := range nonSubRangeAddressPrefixes {
		isSubRangePrefix, err := isSubRange(prefix)
		if err != nil {
			t.Fatal("shouldn't return error when checking if address is sub-range: ", err)
		}
		if isSubRangePrefix {
			t.Fatalf("address %s should not be sub-range of an existing route in the table", prefix)
		}
	}
}

func EnvironmentHasIPv6DefaultRoute() (bool, error) {
	//goland:noinspection GoBoolExpressions
	if runtime.GOOS != "linux" {
		// TODO when implementing IPv6 for other operating systems, this should be replaced with code that determines
		// 		whether a default route for IPv6 exists (routing.Router panics on non-linux).
		return false, nil
	}
	router, err := routing.New()
	if err != nil {
		return false, err
	}
	routeIface, _, _, err := router.Route(netip.MustParsePrefix("::/0").Addr().AsSlice())
	if err != nil {
		return false, err
	}
	return routeIface != nil, nil
}

func TestExistsInRouteTable(t *testing.T) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal("shouldn't return error when fetching interface addresses: ", err)
	}

	hasV6DefaultRoute, err := EnvironmentHasIPv6DefaultRoute()
	shouldIncludeV6Routes := iface.SupportsIPv6() && firewall.SupportsIPv6() && hasV6DefaultRoute && err == nil

	var addressPrefixes []netip.Prefix
	for _, address := range addresses {
		p := netip.MustParsePrefix(address.String())
		if p.Addr().Is6() && !shouldIncludeV6Routes {
			continue
		}
		// Windows sometimes has hidden interface link local addrs that don't turn up on any interface
		if runtime.GOOS == "windows" && p.Addr().IsLinkLocalUnicast() {
			continue
		}
		// Linux loopback 127/8 is in the local table, not in the main table and always takes precedence
		if runtime.GOOS == "linux" && p.Addr().IsLoopback() {
			continue
		}

		addressPrefixes = append(addressPrefixes, p.Masked())
	}

	for _, prefix := range addressPrefixes {
		exists, err := existsInRouteTable(prefix)
		if err != nil {
			t.Fatal("shouldn't return error when checking if address exists in route table: ", err)
		}
		if !exists {
			t.Fatalf("address %s should exist in route table", prefix)
		}
	}
}

func createWGInterface(t *testing.T, interfaceName, ipAddressCIDR string, ipAddress6CIDR string, listenPort int) *iface.WGIface {
	t.Helper()

	peerPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	newNet, err := stdnet.NewNet()
	require.NoError(t, err)

	wgInterface, err := iface.NewWGIFace(interfaceName, ipAddressCIDR, ipAddress6CIDR, listenPort, peerPrivateKey.String(), iface.DefaultMTU, newNet, nil)
	require.NoError(t, err, "should create testing WireGuard interface")

	err = wgInterface.Create()
	require.NoError(t, err, "should create testing WireGuard interface")

	t.Cleanup(func() {
		wgInterface.Close()
	})

	return wgInterface
}

func setupTestEnv(t *testing.T) {
	t.Helper()

	setupDummyInterfacesAndRoutes(t)

	v6Addr := ""
	hasV6DefaultRoute, err := EnvironmentHasIPv6DefaultRoute()
	//goland:noinspection GoBoolExpressions
	if !iface.SupportsIPv6() || !firewall.SupportsIPv6() || !hasV6DefaultRoute || err != nil {
		t.Skip("Platform does not support IPv6, skipping IPv6 test...")
	} else {
		v6Addr = "2001:db8::4242:4711/128"
	}

	wgIface := createWGInterface(t, expectedVPNint, "100.64.0.1/24", v6Addr, 51820)
	t.Cleanup(func() {
		assert.NoError(t, wgIface.Close())
	})

	_, _, err = setupRouting(nil, wgIface)
	require.NoError(t, err, "setupRouting should not return err")
	t.Cleanup(func() {
		assert.NoError(t, cleanupRouting())
	})

	index, err := net.InterfaceByName(wgIface.Name())
	require.NoError(t, err, "InterfaceByName should not return err")
	intf := &net.Interface{Index: index.Index, Name: wgIface.Name()}

	// default route exists in main table and vpn table
	err = addVPNRoute(netip.MustParsePrefix("0.0.0.0/0"), intf)
	require.NoError(t, err, "addVPNRoute should not return err")
	t.Cleanup(func() {
		err = removeVPNRoute(netip.MustParsePrefix("0.0.0.0/0"), intf)
		assert.NoError(t, err, "removeVPNRoute should not return err")
	})

	// 10.0.0.0/8 route exists in main table and vpn table
	err = addVPNRoute(netip.MustParsePrefix("10.0.0.0/8"), intf)
	require.NoError(t, err, "addVPNRoute should not return err")
	t.Cleanup(func() {
		err = removeVPNRoute(netip.MustParsePrefix("10.0.0.0/8"), intf)
		assert.NoError(t, err, "removeVPNRoute should not return err")
	})

	// 10.10.0.0/24 more specific route exists in vpn table
	err = addVPNRoute(netip.MustParsePrefix("10.10.0.0/24"), intf)
	require.NoError(t, err, "addVPNRoute should not return err")
	t.Cleanup(func() {
		err = removeVPNRoute(netip.MustParsePrefix("10.10.0.0/24"), intf)
		assert.NoError(t, err, "removeVPNRoute should not return err")
	})

	// 127.0.10.0/24 more specific route exists in vpn table
	err = addVPNRoute(netip.MustParsePrefix("127.0.10.0/24"), intf)
	require.NoError(t, err, "addVPNRoute should not return err")
	t.Cleanup(func() {
		err = removeVPNRoute(netip.MustParsePrefix("127.0.10.0/24"), intf)
		assert.NoError(t, err, "removeVPNRoute should not return err")
	})

	// unique route in vpn table
	err = addVPNRoute(netip.MustParsePrefix("172.16.0.0/12"), intf)
	require.NoError(t, err, "addVPNRoute should not return err")
	t.Cleanup(func() {
		err = removeVPNRoute(netip.MustParsePrefix("172.16.0.0/12"), intf)
		assert.NoError(t, err, "removeVPNRoute should not return err")
	})
}

func assertWGOutInterface(t *testing.T, prefix netip.Prefix, wgIface *iface.WGIface, invert bool) {
	t.Helper()
	if runtime.GOOS == "linux" && prefix.Addr().IsLoopback() {
		return
	}

	prefixGateway, _, err := GetNextHop(prefix.Addr())
	require.NoError(t, err, "GetNextHop should not return err")

	nexthop := wgIface.Address().IP.String()
	if prefix.Addr().Is6() {
		nexthop = wgIface.Address6().IP.String()
	}

	if invert {
		assert.NotEqual(t, nexthop, prefixGateway.String(), "route should not point to wireguard interface IP")
	} else {
		assert.Equal(t, nexthop, prefixGateway.String(), "route should point to wireguard interface IP")
	}
}
