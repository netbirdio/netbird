package systemops

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

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbnet "github.com/netbirdio/netbird/client/net"
)

var (
	expectedExternalInt = "Ethernet1"
	expectedVPNint      = "wgtest0"
)

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
	NextHop           string `json:"Nexthop"`
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
		expectedInterface:  expectedVPNint,
		dialer:             &net.Dialer{},
	},
	{
		name:               "To external host with custom dialer via physical interface",
		destination:        "192.0.2.1:53",
		expectedDestPrefix: "192.0.2.1/32",
		expectedInterface:  expectedExternalInt,
		dialer:             nbnet.NewDialer(),
	},

	{
		name:               "To duplicate internal route with custom dialer via physical interface",
		destination:        "10.0.0.2:53",
		expectedDestPrefix: "10.0.0.2/32",
		expectedInterface:  expectedExternalInt,
		dialer:             nbnet.NewDialer(),
	},

	{
		name:               "To unique vpn route with custom dialer via physical interface",
		destination:        "172.16.0.2:53",
		expectedDestPrefix: "172.16.0.2/32",
		expectedInterface:  expectedExternalInt,
		dialer:             nbnet.NewDialer(),
	},
	{
		name:               "To unique vpn route without custom dialer via vpn",
		destination:        "172.16.0.2:53",
		expectedSourceIP:   "100.64.0.1",
		expectedDestPrefix: "172.16.0.0/12",
		expectedNextHop:    "0.0.0.0",
		expectedInterface:  expectedVPNint,
		dialer:             &net.Dialer{},
	},

	{
		name:               "To more specific route without custom dialer via vpn interface",
		destination:        "10.10.0.2:53",
		expectedSourceIP:   "100.64.0.1",
		expectedDestPrefix: "10.10.0.0/24",
		expectedNextHop:    "0.0.0.0",
		expectedInterface:  expectedVPNint,
		dialer:             &net.Dialer{},
	},
}

func TestRouting(t *testing.T) {
	log.SetLevel(log.DebugLevel)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setupTestEnv(t)

			route, err := fetchOriginalGateway()
			require.NoError(t, err, "Failed to fetch original gateway")
			ip, err := fetchInterfaceIP(route.InterfaceAlias)
			require.NoError(t, err, "Failed to fetch interface IP")

			output := testRoute(t, tc.destination, tc.dialer)
			if tc.expectedInterface == expectedExternalInt {
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

	script := fmt.Sprintf(`Find-NetRoute -RemoteIPAddress "%s" | Select-Object -Property IPAddress, InterfaceIndex, InterfaceAlias, AddressFamily, Nexthop, DestinationPrefix | ConvertTo-Json`, host)

	out, err := exec.Command("powershell", "-Command", script).Output()
	require.NoError(t, err, "Failed to execute Find-NetRoute")

	var outputs []FindNetRouteOutput
	err = json.Unmarshal(out, &outputs)
	require.NoError(t, err, "Failed to parse JSON outputs from Find-NetRoute")

	require.Greater(t, len(outputs), 0, "No route found for destination")
	combinedOutput := combineOutputs(outputs)

	return combinedOutput
}

func fetchOriginalGateway() (*RouteInfo, error) {
	cmd := exec.Command("powershell", "-Command", "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object Nexthop, RouteMetric, InterfaceAlias | ConvertTo-Json")
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

	addDummyRoute(t, "10.0.0.0/8")
}

func addDummyRoute(t *testing.T, dstCIDR string) {
	t.Helper()

	prefix, err := netip.ParsePrefix(dstCIDR)
	if err != nil {
		t.Fatalf("Failed to parse destination CIDR %s: %v", dstCIDR, err)
	}

	nexthop := Nexthop{
		Intf: &net.Interface{Index: 1},
	}

	if err = addRoute(prefix, nexthop); err != nil {
		t.Fatalf("Failed to add dummy route: %v", err)
	}

	t.Cleanup(func() {
		err := deleteRoute(prefix, nexthop)
		if err != nil {
			t.Logf("Failed to remove dummy route: %v", err)
		}
	})
}
