//go:build !android

package routemanager

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
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

	if runtime.GOOS == "linux" {
		outIntf, err := getOutgoingInterfaceLinux(prefix.Addr().String())
		require.NoError(t, err, "getOutgoingInterfaceLinux should not return error")
		if invert {
			require.NotEqual(t, wgIface.Name(), outIntf, "outgoing interface should not be the wireguard interface")
		} else {
			require.Equal(t, wgIface.Name(), outIntf, "outgoing interface should be the wireguard interface")
		}
		return
	}

	prefixGateway, err := getExistingRIBRouteGateway(prefix)
	require.NoError(t, err, "getExistingRIBRouteGateway should not return err")
	if invert {
		assert.NotEqual(t, wgIface.Address().IP.String(), prefixGateway.String(), "route should not point to wireguard interface IP")
	} else {
		assert.Equal(t, wgIface.Address().IP.String(), prefixGateway.String(), "route should point to wireguard interface IP")
	}
}

func getOutgoingInterfaceLinux(destination string) (string, error) {
	cmd := exec.Command("ip", "route", "get", destination)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("executing ip route get: %w", err)
	}

	return parseOutgoingInterface(string(output)), nil
}

func parseOutgoingInterface(routeGetOutput string) string {
	fields := strings.Fields(routeGetOutput)
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
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

			err = addToRouteTableIfNoExists(testCase.prefix, wgInterface.Address().IP.String(), wgInterface.Name())
			require.NoError(t, err, "addToRouteTableIfNoExists should not return err")

			if testCase.shouldRouteToWireguard {
				assertWGOutInterface(t, testCase.prefix, wgInterface, false)
			} else {
				assertWGOutInterface(t, testCase.prefix, wgInterface, true)
			}
			exists, err := existsInRouteTable(testCase.prefix)
			require.NoError(t, err, "existsInRouteTable should not return err")
			if exists && testCase.shouldRouteToWireguard {
				err = removeFromRouteTableIfNonSystem(testCase.prefix, wgInterface.Address().IP.String(), wgInterface.Name())
				require.NoError(t, err, "removeFromRouteTableIfNonSystem should not return err")

				prefixGateway, err := getExistingRIBRouteGateway(testCase.prefix)
				require.NoError(t, err, "getExistingRIBRouteGateway should not return err")

				internetGateway, err := getExistingRIBRouteGateway(netip.MustParsePrefix("0.0.0.0/0"))
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

func TestAddExistAndRemoveRouteNonAndroid(t *testing.T) {
	defaultGateway, err := getExistingRIBRouteGateway(netip.MustParsePrefix("0.0.0.0/0"))
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

			MockAddr := wgInterface.Address().IP.String()

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
				err = removeFromRouteTableIfNonSystem(testCase.prefix, MockAddr, wgInterface.Name())
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
