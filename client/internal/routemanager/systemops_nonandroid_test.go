package routemanager

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/pion/transport/v2/stdnet"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

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
			name:                   "Should Add And Remove Route",
			prefix:                 netip.MustParsePrefix("100.66.120.0/24"),
			shouldRouteToWireguard: true,
			shouldBeRemoved:        true,
		},
		{
			name:                   "Should Not Add Or Remove Route",
			prefix:                 netip.MustParsePrefix("127.0.0.1/32"),
			shouldRouteToWireguard: false,
			shouldBeRemoved:        false,
		},
	}

	for n, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			newNet, err := stdnet.NewNet()
			if err != nil {
				t.Fatal(err)
			}
			wgInterface, err := iface.NewWGIFace(fmt.Sprintf("utun53%d", n), "100.65.75.2/24", iface.DefaultMTU, nil, newNet)
			require.NoError(t, err, "should create testing WGIface interface")
			defer wgInterface.Close()

			err = wgInterface.Create()
			require.NoError(t, err, "should create testing wireguard interface")

			err = addToRouteTableIfNoExists(testCase.prefix, wgInterface.Address().IP.String())
			require.NoError(t, err, "should not return err")

			prefixGateway, err := getExistingRIBRouteGateway(testCase.prefix)
			require.NoError(t, err, "should not return err")
			if testCase.shouldRouteToWireguard {
				require.Equal(t, wgInterface.Address().IP.String(), prefixGateway.String(), "route should point to wireguard interface IP")
			} else {
				require.NotEqual(t, wgInterface.Address().IP.String(), prefixGateway.String(), "route should point to a different interface")
			}

			err = removeFromRouteTableIfNonSystem(testCase.prefix, wgInterface.Address().IP.String())
			require.NoError(t, err, "should not return err")

			prefixGateway, err = getExistingRIBRouteGateway(testCase.prefix)
			require.NoError(t, err, "should not return err")

			internetGateway, err := getExistingRIBRouteGateway(netip.MustParsePrefix("0.0.0.0/0"))
			require.NoError(t, err)

			if testCase.shouldBeRemoved {
				require.Equal(t, internetGateway, prefixGateway, "route should be pointing to default internet gateway")
			} else {
				require.NotEqual(t, internetGateway, prefixGateway, "route should be pointing to a different gateway than the internet gateway")
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

func TestAddExistAndRemoveRoute(t *testing.T) {
	defaultGateway, err := getExistingRIBRouteGateway(netip.MustParsePrefix("0.0.0.0/0"))
	fmt.Println("defaultGateway: ", defaultGateway)
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

	// MOCK_ADDR := "127.0.0.1"

	for n, testCase := range testCases {
		var buf bytes.Buffer
		log.SetOutput(&buf)
		defer func() {
			log.SetOutput(os.Stderr)
		}()
		t.Run(testCase.name, func(t *testing.T) {
			newNet, err := stdnet.NewNet()
			if err != nil {
				t.Fatal(err)
			}
			wgInterface, err := iface.NewWGIFace(fmt.Sprintf("utun53%d", n), "100.65.75.2/24", iface.DefaultMTU, nil, newNet)
			require.NoError(t, err, "should create testing WGIface interface")
			defer wgInterface.Close()

			err = wgInterface.Create()
			require.NoError(t, err, "should create testing wireguard interface")

			MOCK_ADDR := wgInterface.Address().IP.String()

			// Prepare the environment
			if testCase.preExistingPrefix.IsValid() {
				err := addToRouteTableIfNoExists(testCase.preExistingPrefix, MOCK_ADDR)
				require.NoError(t, err, "should not return err when adding pre-existing route")
			}

			// Add the route
			err = addToRouteTableIfNoExists(testCase.prefix, MOCK_ADDR)
			require.NoError(t, err, "should not return err when adding pre-existing route")

			if testCase.shouldAddRoute {
				// test if route exists after adding
				ok, err := existsInRouteTable(testCase.prefix)
				require.NoError(t, err, "should not return err")
				require.True(t, ok, "route should exist")

				// remove route again if added
				err = removeFromRouteTableIfNonSystem(testCase.prefix, MOCK_ADDR)
				require.NoError(t, err, "should not return err")
			}

			// route should either not have been added or should have been removed
			// In case of already existing route, it should not have been added (but still exist)
			ok, err := existsInRouteTable(testCase.prefix)
			fmt.Println("Buffer string: ", buf.String())
			require.NoError(t, err, "should not return err")
			if !strings.Contains(buf.String(), "because it already exists") {
				require.False(t, ok, "route should not exist")
			}
		})
	}
}
