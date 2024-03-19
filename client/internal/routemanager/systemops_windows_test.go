package routemanager

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbnet "github.com/netbirdio/netbird/util/net"
)

type RouteInfo struct {
	NextHop        string `json:"nexthop"`
	InterfaceAlias string `json:"interfacealias"`
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
		expectedSourceIP:   "192.168.0.1",
		expectedDestPrefix: "192.0.2.1/32",
		expectedNextHop:    "0.0.0.0",
		expectedInterface:  "dummyext0",
		dialer:             nbnet.NewDialer(),
	},

	{
		name:               "To duplicate internal route with custom dialer via physical interface",
		destination:        "10.0.0.2:53",
		expectedSourceIP:   "192.168.0.1",
		expectedDestPrefix: "10.0.0.2/32",
		expectedNextHop:    "192.168.0.10",
		expectedInterface:  "dummyext0",
		dialer:             nbnet.NewDialer(),
	},
	{
		name:               "To duplicate internal route without custom dialer via physical interface", // local route takes precedence
		destination:        "10.0.0.2:53",
		expectedSourceIP:   "192.168.0.1",
		expectedDestPrefix: "10.0.0.0/8",
		expectedNextHop:    "192.168.0.10",
		expectedInterface:  "dummyext0",
		dialer:             &net.Dialer{},
	},

	{
		name:               "To unique vpn route with custom dialer via physical interface",
		destination:        "172.16.0.2:53",
		expectedSourceIP:   "192.168.0.1",
		expectedDestPrefix: "172.16.0.2/32",
		expectedNextHop:    "0.0.0.0",
		expectedInterface:  "dummyext0",
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
		expectedSourceIP:   "127.0.0.1",
		expectedDestPrefix: "127.0.0.0/8",
		expectedNextHop:    "0.0.0.0",
		expectedInterface:  "Loopback Pseudo-Interface 1",
		dialer:             &net.Dialer{},
	},
}

func TestRouting(t *testing.T) {
	cleanupInterfaces(t)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setupTestEnv(t)

			output := testRoute(t, tc.destination, tc.dialer)
			verifyOutput(t, output, tc.expectedSourceIP, tc.expectedDestPrefix, tc.expectedNextHop, tc.expectedInterface)
		})
	}
}

func testRoute(t *testing.T, destination string, dialer dialer) *FindNetRouteOutput {
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
	const defaultInterfaceName = "Ethernet"
	t.Helper()

	_, err := exec.Command("devcon64.exe", "install", `c:\windows\inf\netloop.inf`, "*msloop").CombinedOutput()
	require.NoError(t, err, "Failed to create loopback adapter")

	// Give the system a moment to register the new adapter
	time.Sleep(time.Second * 1)

	_, err = exec.Command("powershell", "-Command", fmt.Sprintf(`Rename-NetAdapter -Name "%s" -NewName "%s"`, defaultInterfaceName, interfaceName)).CombinedOutput()
	require.NoError(t, err, "Failed to rename loopback adapter")

	ip, ipNet, err := net.ParseCIDR(ipAddressCIDR)
	require.NoError(t, err)
	subnetMaskSize, _ := ipNet.Mask.Size()
	script := fmt.Sprintf(`New-NetIPAddress -InterfaceAlias "%s" -IPAddress "%s" -PrefixLength %d -Confirm:$False`, interfaceName, ip.String(), subnetMaskSize)
	exec.Command("powershell", "-Command", script).CombinedOutput()

	// Wait for the IP address to be applied
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = waitForIPAddress(ctx, interfaceName, ip.String())
	require.NoError(t, err, "IP address not applied within timeout")

	t.Cleanup(func() {
		cleanupInterfaces(t)
	})

	return interfaceName
}

func cleanupInterfaces(t *testing.T) {
	_, err := exec.Command("devcon64.exe", "/r", "remove", "=net", `@ROOT\NET\*`).CombinedOutput()
	assert.NoError(t, err, "Failed to remove loopback adapter")
}

func fetchOriginalGateway(t *testing.T) *RouteInfo {
	t.Helper()

	cmd := exec.Command("powershell", "-Command", "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object NextHop, InterfaceAlias | ConvertTo-Json")
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to execute Get-NetRoute")

	var routeInfo RouteInfo
	err = json.Unmarshal(output, &routeInfo)
	require.NoError(t, err, "Failed to parse JSON output from Get-NetRoute")

	return &routeInfo
}

func addDummyRoute(t *testing.T, dstCIDR string, gw net.IP, intf string) {
	t.Helper()

	prefix, err := netip.ParsePrefix(dstCIDR)
	require.NoError(t, err)

	var originalRoute *RouteInfo
	if prefix.String() == "0.0.0.0/0" {
		originalRoute = fetchOriginalGateway(t)

		script := fmt.Sprintf(`Remove-NetRoute -DestinationPrefix "%s" -Confirm:$False`, prefix)
		_, err := exec.Command("powershell", "-Command", script).CombinedOutput()
		require.NoError(t, err, "Failed to remove existing route")
	}

	t.Cleanup(func() {
		if originalRoute != nil {
			script := fmt.Sprintf(
				`New-NetRoute -DestinationPrefix "0.0.0.0/0" -InterfaceAlias "%s" -NextHop "%s" -Confirm:$False`,
				originalRoute.InterfaceAlias,
				originalRoute.NextHop,
			)
			_, err := exec.Command("powershell", "-Command", script).CombinedOutput()
			if err != nil {
				t.Logf("Failed to restore original route: %v", err)
			}
		}
	})

	script := fmt.Sprintf(
		`New-NetRoute -DestinationPrefix "%s" -InterfaceAlias "%s" -NextHop "%s" -RouteMetric %d -PolicyStore ActiveStore -Confirm:$False`,
		prefix,
		intf,
		gw,
		1,
	)
	_, err = exec.Command("powershell", "-Command", script).CombinedOutput()
	require.NoError(t, err, "Failed to add route")
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

	// Can't use two interfaces as windows will always pick the default route even if there is a more specific one
	dummy := createAndSetupDummyInterface(t, "dummyext0", "192.168.0.1/24")
	addDummyRoute(t, "0.0.0.0/0", net.IPv4(192, 168, 0, 1), dummy)
	addDummyRoute(t, "10.0.0.0/8", net.IPv4(192, 168, 0, 10), dummy)
}
