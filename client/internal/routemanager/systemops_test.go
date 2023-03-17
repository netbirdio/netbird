package routemanager

import (
	"fmt"
	"github.com/netbirdio/netbird/iface"
	"github.com/stretchr/testify/require"
	"net"
	"net/netip"
	"testing"
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
			wgInterface, err := iface.NewWGIFace(fmt.Sprintf("utun53%d", n), "100.65.75.2/24", iface.DefaultMTU, nil)
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
