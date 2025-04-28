//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package systemops

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"regexp"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/route"
)

var expectedVPNint = "utun100"
var expectedExternalInt = "lo0"
var expectedInternalInt = "lo0"

func init() {
	testCases = append(testCases, []testCase{
		{
			name:              "To more specific route without custom dialer via vpn",
			expectedInterface: expectedVPNint,
			dialer:            &net.Dialer{},
			expectedPacket:    createPacketExpectation("100.64.0.1", 12345, "10.10.0.2", 53),
		},
	}...)
}

func TestConcurrentRoutes(t *testing.T) {
	baseIP := netip.MustParseAddr("192.0.2.0")
	intf := &net.Interface{Name: "lo0"}

	r := NewSysOps(nil, nil)

	var wg sync.WaitGroup
	for i := 0; i < 1024; i++ {
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			prefix := netip.PrefixFrom(ip, 32)
			if err := r.addToRouteTable(prefix, Nexthop{netip.Addr{}, intf}); err != nil {
				t.Errorf("Failed to add route for %s: %v", prefix, err)
			}
		}(baseIP)
		baseIP = baseIP.Next()
	}

	wg.Wait()

	baseIP = netip.MustParseAddr("192.0.2.0")

	for i := 0; i < 1024; i++ {
		wg.Add(1)
		go func(ip netip.Addr) {
			defer wg.Done()
			prefix := netip.PrefixFrom(ip, 32)
			if err := r.removeFromRouteTable(prefix, Nexthop{netip.Addr{}, intf}); err != nil {
				t.Errorf("Failed to remove route for %s: %v", prefix, err)
			}
		}(baseIP)
		baseIP = baseIP.Next()
	}

	wg.Wait()
}

func TestBits(t *testing.T) {
	tests := []struct {
		name    string
		addr    route.Addr
		want    int
		wantErr bool
	}{
		{
			name: "IPv4 all ones",
			addr: &route.Inet4Addr{IP: [4]byte{255, 255, 255, 255}},
			want: 32,
		},
		{
			name: "IPv4 normal mask",
			addr: &route.Inet4Addr{IP: [4]byte{255, 255, 255, 0}},
			want: 24,
		},
		{
			name: "IPv6 all ones",
			addr: &route.Inet6Addr{IP: [16]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}},
			want: 128,
		},
		{
			name: "IPv6 normal mask",
			addr: &route.Inet6Addr{IP: [16]byte{255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0}},
			want: 64,
		},
		{
			name:    "Unsupported type",
			addr:    &route.LinkAddr{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ones(tt.addr)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func createAndSetupDummyInterface(t *testing.T, intf string, ipAddressCIDR string) string {
	t.Helper()

	err := exec.Command("ifconfig", intf, "alias", ipAddressCIDR).Run()
	require.NoError(t, err, "Failed to create loopback alias")

	t.Cleanup(func() {
		err := exec.Command("ifconfig", intf, ipAddressCIDR, "-alias").Run()
		assert.NoError(t, err, "Failed to remove loopback alias")
	})

	return "lo0"
}

func addDummyRoute(t *testing.T, dstCIDR string, gw net.IP, _ string) {
	t.Helper()

	var originalNexthop net.IP
	if dstCIDR == "0.0.0.0/0" {
		var err error
		originalNexthop, err = fetchOriginalGateway()
		if err != nil {
			t.Logf("Failed to fetch original gateway: %v", err)
		}

		if output, err := exec.Command("route", "delete", "-net", dstCIDR).CombinedOutput(); err != nil {
			t.Logf("Failed to delete route: %v, output: %s", err, output)
		}
	}

	t.Cleanup(func() {
		if originalNexthop != nil {
			err := exec.Command("route", "add", "-net", dstCIDR, originalNexthop.String()).Run()
			assert.NoError(t, err, "Failed to restore original route")
		}
	})

	err := exec.Command("route", "add", "-net", dstCIDR, gw.String()).Run()
	require.NoError(t, err, "Failed to add route")

	t.Cleanup(func() {
		err := exec.Command("route", "delete", "-net", dstCIDR).Run()
		assert.NoError(t, err, "Failed to remove route")
	})
}

func fetchOriginalGateway() (net.IP, error) {
	output, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return nil, err
	}

	matches := regexp.MustCompile(`gateway: (\S+)`).FindStringSubmatch(string(output))
	if len(matches) == 0 {
		return nil, fmt.Errorf("gateway not found")
	}

	return net.ParseIP(matches[1]), nil
}

func setupDummyInterfacesAndRoutes(t *testing.T) {
	t.Helper()

	defaultDummy := createAndSetupDummyInterface(t, expectedExternalInt, "192.168.0.1/24")
	addDummyRoute(t, "0.0.0.0/0", net.IPv4(192, 168, 0, 1), defaultDummy)

	otherDummy := createAndSetupDummyInterface(t, expectedInternalInt, "192.168.1.1/24")
	addDummyRoute(t, "10.0.0.0/8", net.IPv4(192, 168, 1, 1), otherDummy)
}
