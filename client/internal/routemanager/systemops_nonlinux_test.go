//go:build !linux && !ios

package routemanager

import (
	"bytes"
	"fmt"
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

func assertWGOutInterface(t *testing.T, prefix netip.Prefix, wgIface *iface.WGIface, invert bool) {
	t.Helper()

	prefixGateway, _, err := getNextHop(prefix.Addr())
	require.NoError(t, err, "getNextHop should not return err")
	if invert {
		assert.NotEqual(t, wgIface.Address().IP.String(), prefixGateway.String(), "route should not point to wireguard interface IP")
	} else {
		assert.Equal(t, wgIface.Address().IP.String(), prefixGateway.String(), "route should point to wireguard interface IP")
	}
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
			peerPrivateKey, _ := wgtypes.GeneratePrivateKey()
			newNet, err := stdnet.NewNet()
			if err != nil {
				t.Fatal(err)
			}
			wgInterface, err := iface.NewWGIFace(fmt.Sprintf("utun53%d", n), "100.65.75.2/24", 33100, peerPrivateKey.String(), iface.DefaultMTU, newNet, nil)
			require.NoError(t, err, "should create testing WGIface interface")
			defer wgInterface.Close()

			err = wgInterface.Create()
			require.NoError(t, err, "should create testing wireguard interface")
			_, _, err = setupRouting(nil, nil)
			require.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, cleanupRouting())
			})

			err = addVPNRoute(testCase.prefix, wgInterface.Name())
			require.NoError(t, err, "addVPNRoute should not return err")

			if testCase.shouldRouteToWireguard {
				assertWGOutInterface(t, testCase.prefix, wgInterface, false)
			} else {
				assertWGOutInterface(t, testCase.prefix, wgInterface, true)
			}
			exists, err := existsInRouteTable(testCase.prefix)
			require.NoError(t, err, "existsInRouteTable should not return err")
			if exists && testCase.shouldRouteToWireguard {
				err = removeVPNRoute(testCase.prefix, wgInterface.Name())
				require.NoError(t, err, "removeVPNRoute should not return err")

				prefixGateway, _, err := getNextHop(testCase.prefix.Addr())
				require.NoError(t, err, "getNextHop should not return err")

				internetGateway, _, err := getNextHop(netip.MustParseAddr("0.0.0.0"))
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
	gateway, _, err := getNextHop(netip.MustParseAddr("0.0.0.0"))
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

	localIP, _, err := getNextHop(testingPrefix.Addr())
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

func TestAddExistAndRemoveRouteNonAndroid(t *testing.T) {
	defaultGateway, _, err := getNextHop(netip.MustParseAddr("0.0.0.0"))
	t.Log("defaultGateway: ", defaultGateway)
	if err != nil {
		t.Fatal("shouldn't return error when fetching the gateway: ", err)
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
	}

	for n, testCase := range testCases {
		var buf bytes.Buffer
		log.SetOutput(&buf)
		defer func() {
			log.SetOutput(os.Stderr)
		}()
		t.Run(testCase.name, func(t *testing.T) {
			peerPrivateKey, _ := wgtypes.GeneratePrivateKey()
			newNet, err := stdnet.NewNet()
			if err != nil {
				t.Fatal(err)
			}
			wgInterface, err := iface.NewWGIFace(fmt.Sprintf("utun53%d", n), "100.65.75.2/24", 33100, peerPrivateKey.String(), iface.DefaultMTU, newNet, nil)
			require.NoError(t, err, "should create testing WGIface interface")
			defer wgInterface.Close()

			err = wgInterface.Create()
			require.NoError(t, err, "should create testing wireguard interface")

			_, _, err = setupRouting(nil, nil)
			require.NoError(t, err)
			t.Cleanup(func() {
				assert.NoError(t, cleanupRouting())
			})

			// Prepare the environment
			if testCase.preExistingPrefix.IsValid() {
				err := addVPNRoute(testCase.preExistingPrefix, wgInterface.Name())
				require.NoError(t, err, "should not return err when adding pre-existing route")
			}

			// Add the route
			err = addVPNRoute(testCase.prefix, wgInterface.Name())
			require.NoError(t, err, "should not return err when adding route")

			if testCase.shouldAddRoute {
				// test if route exists after adding
				ok, err := existsInRouteTable(testCase.prefix)
				require.NoError(t, err, "should not return err")
				require.True(t, ok, "route should exist")

				// remove route again if added
				err = removeVPNRoute(testCase.prefix, wgInterface.Name())
				require.NoError(t, err, "should not return err")
			}

			// route should either not have been added or should have been removed
			// In case of already existing route, it should not have been added (but still exist)
			ok, err := existsInRouteTable(testCase.prefix)
			t.Log("Buffer string: ", buf.String())
			require.NoError(t, err, "should not return err")

			// Linux uses a separate routing table, so the route can exist in both tables.
			// The main routing table takes precedence over the wireguard routing table.
			if !strings.Contains(buf.String(), "because it already exists") && runtime.GOOS != "linux" {
				require.False(t, ok, "route should not exist")
			}
		})
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

func TestExistsInRouteTable(t *testing.T) {
	_, _, err := setupRouting(nil, nil)
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, cleanupRouting())
	})

	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal("shouldn't return error when fetching interface addresses: ", err)
	}

	var addressPrefixes []netip.Prefix
	for _, address := range addresses {
		p := netip.MustParsePrefix(address.String())
		if p.Addr().Is4() {
			addressPrefixes = append(addressPrefixes, p.Masked())
		}
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
