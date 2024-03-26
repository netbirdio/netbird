package routemanager

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbnet "github.com/netbirdio/netbird/util/net"
)

var expectedExtInt = "Ethernet1"

type RouteInfo struct {
	NextHop        string `json:"nexthop"`
	InterfaceAlias string `json:"interfacealias"`
	RouteMetric    int    `json:"routemetric"`
}

type FindNetRouteOutput struct {
	IPAddress         string `json:"IPAddress"`
	InterfaceIndex    int    `json:"InterfaceIndex"`
	InterfaceAlias    string `json:"InterfaceAlias"`
	AddressFamily     int    `json:"AddressFamily"`
	NextHop           string `json:"NextHop"`
	DestinationPrefix string `json:"DestinationPrefix"`
}

type testCase struct {
	name               string
	destination        string
	expectedSourceIP   string
	expectedDestPrefix string
	expectedNextHop    string
	expectedInterface  string
	dialer             dialer
}

var expectedVPNint = "wgtest0"

var testCases = []testCase{
	{
		name:               "To external host without custom dialer via vpn",
		destination:        "192.0.2.1:53",
		expectedSourceIP:   "100.64.0.1",
		expectedDestPrefix: "128.0.0.0/1",
		expectedNextHop:    "0.0.0.0",
		expectedInterface:  "wgtest0",
		dialer:             &net.Dialer{},
	},
	{
		name:               "To external host with custom dialer via physical interface",
		destination:        "192.0.2.1:53",
		expectedDestPrefix: "192.0.2.1/32",
		expectedInterface:  expectedExtInt,
		dialer:             nbnet.NewDialer(),
	},

	{
		name:               "To duplicate internal route with custom dialer via physical interface",
		destination:        "10.0.0.2:53",
		expectedDestPrefix: "10.0.0.2/32",
		expectedInterface:  expectedExtInt,
		dialer:             nbnet.NewDialer(),
	},
	{
		name:               "To duplicate internal route without custom dialer via physical interface", // local route takes precedence
		destination:        "10.0.0.2:53",
		expectedSourceIP:   "10.0.0.1",
		expectedDestPrefix: "10.0.0.0/8",
		expectedNextHop:    "0.0.0.0",
		expectedInterface:  "Loopback Pseudo-Interface 1",
		dialer:             &net.Dialer{},
	},

	{
		name:               "To unique vpn route with custom dialer via physical interface",
		destination:        "172.16.0.2:53",
		expectedDestPrefix: "172.16.0.2/32",
		expectedInterface:  expectedExtInt,
		dialer:             nbnet.NewDialer(),
	},
	{
		name:               "To unique vpn route without custom dialer via vpn",
		destination:        "172.16.0.2:53",
		expectedSourceIP:   "100.64.0.1",
		expectedDestPrefix: "172.16.0.0/12",
		expectedNextHop:    "0.0.0.0",
		expectedInterface:  "wgtest0",
		dialer:             &net.Dialer{},
	},

	{
		name:               "To more specific route without custom dialer via vpn interface",
		destination:        "10.10.0.2:53",
		expectedSourceIP:   "100.64.0.1",
		expectedDestPrefix: "10.10.0.0/24",
		expectedNextHop:    "0.0.0.0",
		expectedInterface:  "wgtest0",
		dialer:             &net.Dialer{},
	},

	{
		name:               "To more specific route (local) without custom dialer via physical interface",
		destination:        "127.0.10.2:53",
		expectedSourceIP:   "10.0.0.1",
		expectedDestPrefix: "127.0.0.0/8",
		expectedNextHop:    "0.0.0.0",
		expectedInterface:  "Loopback Pseudo-Interface 1",
		dialer:             &net.Dialer{},
	},
}

func TestRouting(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setupTestEnv(t)

			route, err := fetchOriginalGateway()
			require.NoError(t, err, "Failed to fetch original gateway")
			ip, err := fetchInterfaceIP(route.InterfaceAlias)
			require.NoError(t, err, "Failed to fetch interface IP")

			output := testRoute(t, tc.destination, tc.dialer)
			if tc.expectedInterface == expectedExtInt {
				verifyOutput(t, output, ip, tc.expectedDestPrefix, route.NextHop, route.InterfaceAlias)
			} else {
				verifyOutput(t, output, tc.expectedSourceIP, tc.expectedDestPrefix, tc.expectedNextHop, tc.expectedInterface)
			}
		})
	}
}

// fetchInterfaceIP fetches the IPv4 address of the specified interface.
func fetchInterfaceIP(interfaceAlias string) (string, error) {
	script := fmt.Sprintf(`Get-NetIPAddress -InterfaceAlias "%s" | Where-Object AddressFamily -eq 2 | Select-Object -ExpandProperty IPAddress`, interfaceAlias)
	out, err := exec.Command("powershell", "-Command", script).Output()
	if err != nil {
		return "", fmt.Errorf("failed to execute Get-NetIPAddress: %w", err)
	}

	ip := strings.TrimSpace(string(out))
	return ip, nil
}

func testRoute(t *testing.T, destination string, dialer dialer) *FindNetRouteOutput {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "udp", destination)
	require.NoError(t, err, "Failed to dial destination")
	defer func() {
		err := conn.Close()
		assert.NoError(t, err, "Failed to close connection")
	}()

	host, _, err := net.SplitHostPort(destination)
	require.NoError(t, err)

	script := fmt.Sprintf(`Find-NetRoute -RemoteIPAddress "%s" | Select-Object -Property IPAddress, InterfaceIndex, InterfaceAlias, AddressFamily, NextHop, DestinationPrefix | ConvertTo-Json`, host)

	out, err := exec.Command("powershell", "-Command", script).Output()
	require.NoError(t, err, "Failed to execute Find-NetRoute")

	var outputs []FindNetRouteOutput
	err = json.Unmarshal(out, &outputs)
	require.NoError(t, err, "Failed to parse JSON outputs from Find-NetRoute")

	require.Greater(t, len(outputs), 0, "No route found for destination")
	combinedOutput := combineOutputs(outputs)

	return combinedOutput
}

func createAndSetupDummyInterface(t *testing.T, interfaceName, ipAddressCIDR string) string {
	t.Helper()

	ip, ipNet, err := net.ParseCIDR(ipAddressCIDR)
	require.NoError(t, err)
	subnetMaskSize, _ := ipNet.Mask.Size()
	script := fmt.Sprintf(`New-NetIPAddress -InterfaceAlias "%s" -IPAddress "%s" -PrefixLength %d -PolicyStore ActiveStore -Confirm:$False`, interfaceName, ip.String(), subnetMaskSize)
	_, err = exec.Command("powershell", "-Command", script).CombinedOutput()
	require.NoError(t, err, "Failed to assign IP address to loopback adapter")

	// Wait for the IP address to be applied
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = waitForIPAddress(ctx, interfaceName, ip.String())
	require.NoError(t, err, "IP address not applied within timeout")

	t.Cleanup(func() {
		script = fmt.Sprintf(`Remove-NetIPAddress -InterfaceAlias "%s" -IPAddress "%s" -Confirm:$False`, interfaceName, ip.String())
		_, err = exec.Command("powershell", "-Command", script).CombinedOutput()
		require.NoError(t, err, "Failed to remove IP address from loopback adapter")
	})

	return interfaceName
}

func fetchOriginalGateway() (*RouteInfo, error) {
	cmd := exec.Command("powershell", "-Command", "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object NextHop, RouteMetric, InterfaceAlias | ConvertTo-Json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to execute Get-NetRoute: %w", err)
	}

	var routeInfo RouteInfo
	err = json.Unmarshal(output, &routeInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON output: %w", err)
	}

	return &routeInfo, nil
}

func verifyOutput(t *testing.T, output *FindNetRouteOutput, sourceIP, destPrefix, nextHop, intf string) {
	t.Helper()

	assert.Equal(t, sourceIP, output.IPAddress, "Source IP mismatch")
	assert.Equal(t, destPrefix, output.DestinationPrefix, "Destination prefix mismatch")
	assert.Equal(t, nextHop, output.NextHop, "Next hop mismatch")
	assert.Equal(t, intf, output.InterfaceAlias, "Interface mismatch")
}

func waitForIPAddress(ctx context.Context, interfaceAlias, expectedIPAddress string) error {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			out, err := exec.Command("powershell", "-Command", fmt.Sprintf(`Get-NetIPAddress -InterfaceAlias "%s" | Select-Object -ExpandProperty IPAddress`, interfaceAlias)).CombinedOutput()
			if err != nil {
				return err
			}

			ipAddresses := strings.Split(strings.TrimSpace(string(out)), "\n")
			for _, ip := range ipAddresses {
				if strings.TrimSpace(ip) == expectedIPAddress {
					return nil
				}
			}
		}
	}
}

func combineOutputs(outputs []FindNetRouteOutput) *FindNetRouteOutput {
	var combined FindNetRouteOutput

	for _, output := range outputs {
		if output.IPAddress != "" {
			combined.IPAddress = output.IPAddress
		}
		if output.InterfaceIndex != 0 {
			combined.InterfaceIndex = output.InterfaceIndex
		}
		if output.InterfaceAlias != "" {
			combined.InterfaceAlias = output.InterfaceAlias
		}
		if output.AddressFamily != 0 {
			combined.AddressFamily = output.AddressFamily
		}
		if output.NextHop != "" {
			combined.NextHop = output.NextHop
		}
		if output.DestinationPrefix != "" {
			combined.DestinationPrefix = output.DestinationPrefix
		}
	}

	return &combined
}

func setupDummyInterfacesAndRoutes(t *testing.T) {
	t.Helper()

	createAndSetupDummyInterface(t, "Loopback Pseudo-Interface 1", "10.0.0.1/8")
}
