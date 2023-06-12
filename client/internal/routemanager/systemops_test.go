package routemanager

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/pion/transport/v2/stdnet"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/iface"
)

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
			require.NoError(t, err, "should not return err when adding route")

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
