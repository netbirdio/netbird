//go:build !android

package routemanager

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

var expectedVPNint = "wgtest0"
var expectedLoopbackInt = "lo"
var expectedExternalInt = "dummyext0"
var expectedInternalInt = "dummyint0"

func init() {
	testCases = append(testCases, []testCase{
		{
			name:              "To more specific route without custom dialer via physical interface",
			destination:       "10.10.0.2:53",
			expectedInterface: expectedInternalInt,
			dialer:            &net.Dialer{},
			expectedPacket:    createPacketExpectation("192.168.1.1", 12345, "10.10.0.2", 53),
		},
		{
			name:              "To more specific route (local) without custom dialer via physical interface",
			destination:       "127.0.10.1:53",
			expectedInterface: expectedLoopbackInt,
			dialer:            &net.Dialer{},
			expectedPacket:    createPacketExpectation("127.0.0.1", 12345, "127.0.10.1", 53),
		},
	}...)
}

func TestEntryExists(t *testing.T) {
	tempDir := t.TempDir()
	tempFilePath := fmt.Sprintf("%s/rt_tables", tempDir)

	content := []string{
		"1000 reserved",
		fmt.Sprintf("%d %s", NetbirdVPNTableID, NetbirdVPNTableName),
		"9999 other_table",
	}
	require.NoError(t, os.WriteFile(tempFilePath, []byte(strings.Join(content, "\n")), 0644))

	file, err := os.Open(tempFilePath)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, file.Close())
	}()

	tests := []struct {
		name        string
		id          int
		shouldExist bool
		err         error
	}{
		{
			name:        "ExistsWithNetbirdPrefix",
			id:          7120,
			shouldExist: true,
			err:         nil,
		},
		{
			name:        "ExistsWithDifferentName",
			id:          1000,
			shouldExist: true,
			err:         ErrTableIDExists,
		},
		{
			name:        "DoesNotExist",
			id:          1234,
			shouldExist: false,
			err:         nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exists, err := entryExists(file, tc.id)
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.shouldExist, exists)
		})
	}
}

func createAndSetupDummyInterface(t *testing.T, interfaceName, ipAddressCIDR string) string {
	t.Helper()

	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: interfaceName}}
	err := netlink.LinkDel(dummy)
	if err != nil && !errors.Is(err, syscall.EINVAL) {
		t.Logf("Failed to delete dummy interface: %v", err)
	}

	err = netlink.LinkAdd(dummy)
	require.NoError(t, err)

	err = netlink.LinkSetUp(dummy)
	require.NoError(t, err)

	if ipAddressCIDR != "" {
		addr, err := netlink.ParseAddr(ipAddressCIDR)
		require.NoError(t, err)
		err = netlink.AddrAdd(dummy, addr)
		require.NoError(t, err)
	}

	t.Cleanup(func() {
		err := netlink.LinkDel(dummy)
		assert.NoError(t, err)
	})

	return dummy.Name
}

func addDummyRoute(t *testing.T, dstCIDR string, gw net.IP, intf string) {
	t.Helper()

	_, dstIPNet, err := net.ParseCIDR(dstCIDR)
	require.NoError(t, err)

	// Handle existing routes with metric 0
	var originalNexthop net.IP
	var originalLinkIndex int
	if dstIPNet.String() == "0.0.0.0/0" {
		var err error
		originalNexthop, originalLinkIndex, err = fetchOriginalGateway(netlink.FAMILY_V4)
		if err != nil && !errors.Is(err, ErrRouteNotFound) {
			t.Logf("Failed to fetch original gateway: %v", err)
		}

		if originalNexthop != nil {
			err = netlink.RouteDel(&netlink.Route{Dst: dstIPNet, Priority: 0})
			switch {
			case err != nil && !errors.Is(err, syscall.ESRCH):
				t.Logf("Failed to delete route: %v", err)
			case err == nil:
				t.Cleanup(func() {
					err := netlink.RouteAdd(&netlink.Route{Dst: dstIPNet, Gw: originalNexthop, LinkIndex: originalLinkIndex, Priority: 0})
					if err != nil && !errors.Is(err, syscall.EEXIST) {
						t.Fatalf("Failed to add route: %v", err)
					}
				})
			default:
				t.Logf("Failed to delete route: %v", err)
			}
		}
	}

	link, err := netlink.LinkByName(intf)
	require.NoError(t, err)
	linkIndex := link.Attrs().Index

	route := &netlink.Route{
		Dst:       dstIPNet,
		Gw:        gw,
		LinkIndex: linkIndex,
	}
	err = netlink.RouteDel(route)
	if err != nil && !errors.Is(err, syscall.ESRCH) {
		t.Logf("Failed to delete route: %v", err)
	}

	err = netlink.RouteAdd(route)
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("Failed to add route: %v", err)
	}
	require.NoError(t, err)
}

func fetchOriginalGateway(family int) (net.IP, int, error) {
	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		return nil, 0, err
	}

	for _, route := range routes {
		if route.Dst == nil && route.Priority == 0 {
			return route.Gw, route.LinkIndex, nil
		}
	}

	return nil, 0, ErrRouteNotFound
}

func setupDummyInterfacesAndRoutes(t *testing.T) {
	t.Helper()

	defaultDummy := createAndSetupDummyInterface(t, "dummyext0", "192.168.0.1/24")
	addDummyRoute(t, "0.0.0.0/0", net.IPv4(192, 168, 0, 1), defaultDummy)

	otherDummy := createAndSetupDummyInterface(t, "dummyint0", "192.168.1.1/24")
	addDummyRoute(t, "10.0.0.0/8", net.IPv4(192, 168, 1, 1), otherDummy)
}
