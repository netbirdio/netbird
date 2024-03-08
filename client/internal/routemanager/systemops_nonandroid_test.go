//go:build !android

package routemanager

import (
	"bytes"
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
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/iface"
)

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

			ifaceAddr := wgInterface.Address().IP.String()
			if testCase.prefix.Addr().Is6() {
				ifaceAddr = wgInterface.Address6().IP.String()
			}
			err = addToRouteTableIfNoExists(testCase.prefix, ifaceAddr, wgInterface.Name())
			require.NoError(t, err, "addToRouteTableIfNoExists should not return err")

			prefixGateway, err := getExistingRIBRouteGateway(testCase.prefix)
			require.NoError(t, err, "getExistingRIBRouteGateway should not return err")
			if testCase.shouldRouteToWireguard {
				require.Equal(t, ifaceAddr, prefixGateway.String(), "route should point to wireguard interface IP")
			} else {
				require.NotEqual(t, ifaceAddr, prefixGateway.String(), "route should point to a different interface")
			}
			exists, err := existsInRouteTable(testCase.prefix)
			require.NoError(t, err, "existsInRouteTable should not return err")
			if exists && testCase.shouldRouteToWireguard {
				err = removeFromRouteTableIfNonSystem(testCase.prefix, ifaceAddr, wgInterface.Name())
				require.NoError(t, err, "removeFromRouteTableIfNonSystem should not return err")

				prefixGateway, err = getExistingRIBRouteGateway(testCase.prefix)
				require.NoError(t, err, "getExistingRIBRouteGateway should not return err")

				internetGatewayAddr := netip.MustParsePrefix("0.0.0.0/0")
				if testCase.prefix.Addr().Is6() {
					internetGatewayAddr = netip.MustParsePrefix("::/0")
				}
				internetGateway, err := getExistingRIBRouteGateway(internetGatewayAddr)
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

func TestGetExistingRIBRouteGateway(t *testing.T) {
	gateway, err := getExistingRIBRouteGateway(netip.MustParsePrefix("0.0.0.0/0"))
	if err != nil {
		t.Fatal("shouldn't return error when fetching the gateway: ", err)
	}
	if gateway == nil {
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

	localIP, err := getExistingRIBRouteGateway(testingPrefix)
	if err != nil {
		t.Fatal("shouldn't return error: ", err)
	}
	if localIP == nil {
		t.Fatal("should return a gateway for local network")
	}
	if localIP.String() == gateway.String() {
		t.Fatal("local ip should not match with gateway IP")
	}
	if localIP.String() != testingIP {
		t.Fatalf("local ip should match with testing IP: want %s got %s", testingIP, localIP.String())
	}
}

func TestGetExistingRIBRouteGateway6(t *testing.T) {
	//goland:noinspection GoBoolExpressions
	hasV6DefaultRoute, err := EnvironmentHasIPv6DefaultRoute()
	//goland:noinspection GoBoolExpressions
	if !iface.SupportsIPv6() || !firewall.SupportsIPv6() || !hasV6DefaultRoute || err != nil {
		t.Skip("Platform does not support IPv6, skipping IPv6 test...")
	}

	gateway, err := getExistingRIBRouteGateway(netip.MustParsePrefix("::/0"))
	if err != nil {
		t.Fatal("shouldn't return error when fetching the gateway: ", err)
	}
	if gateway == nil {
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
		if !prefix.Addr().IsLoopback() && prefix.Addr().Is6() {
			testingIP = prefix.Addr().String()
			testingPrefix = prefix.Masked()
			break
		}
	}

	localIP, err := getExistingRIBRouteGateway(testingPrefix)
	if err != nil {
		t.Fatal("shouldn't return error: ", err)
	}
	if localIP == nil {
		t.Fatal("should return a gateway for local network")
	}
	if localIP.String() == gateway.String() {
		t.Fatal("local ip should not match with gateway IP")
	}
	if localIP.String() != testingIP {
		t.Fatalf("local ip should match with testing IP: want %s got %s", testingIP, localIP.String())
	}
}

func TestAddExistAndRemoveRouteNonAndroid(t *testing.T) {
	defaultGateway, err := getExistingRIBRouteGateway(netip.MustParsePrefix("0.0.0.0/0"))
	t.Log("defaultGateway: ", defaultGateway)
	if err != nil {
		t.Fatal("shouldn't return error when fetching the gateway: ", err)
	}
	var defaultGateway6 net.IP
	hasV6DefaultRoute, err := EnvironmentHasIPv6DefaultRoute()
	//goland:noinspection GoBoolExpressions
	if iface.SupportsIPv6() && firewall.SupportsIPv6() && hasV6DefaultRoute && err == nil {
		defaultGateway6, err = getExistingRIBRouteGateway(netip.MustParsePrefix("::/0"))
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

			MockAddr := wgInterface.Address().IP.String()
			if testCase.prefix.Addr().Is6() {
				MockAddr = wgInterface.Address6().IP.String()
			}
			MockDevName := wgInterface.Name()

			// Prepare the environment
			if testCase.preExistingPrefix.IsValid() {
				err := addToRouteTableIfNoExists(testCase.preExistingPrefix, MockAddr, wgInterface.Name())
				require.NoError(t, err, "should not return err when adding pre-existing route")
			}

			// Add the route
			err = addToRouteTableIfNoExists(testCase.prefix, MockAddr, wgInterface.Name())
			require.NoError(t, err, "should not return err when adding route")

			if testCase.shouldAddRoute {
				// test if route exists after adding
				ok, err := existsInRouteTable(testCase.prefix)
				require.NoError(t, err, "should not return err")
				require.True(t, ok, "route should exist")

				// remove route again if added
				err = removeFromRouteTableIfNonSystem(testCase.prefix, MockAddr, MockDevName)
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

func TestExistsInRouteTable(t *testing.T) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal("shouldn't return error when fetching interface addresses: ", err)
	}

	var addressPrefixes []netip.Prefix
	for _, address := range addresses {
		p := netip.MustParsePrefix(address.String())
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

func TestIsSubRange(t *testing.T) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal("shouldn't return error when fetching interface addresses: ", err)
	}

	var subRangeAddressPrefixes []netip.Prefix
	var nonSubRangeAddressPrefixes []netip.Prefix
	for _, address := range addresses {
		p := netip.MustParsePrefix(address.String())
		if !p.Addr().IsLoopback() && p.Addr().Is4() && p.Bits() < 32 {
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
