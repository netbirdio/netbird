//go:build !android && !ios && !js

package systemops

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/routemanager/notifier"
	"github.com/netbirdio/netbird/client/internal/routemanager/refcounter"
)

func mustIPNet(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, ipnet, err := net.ParseCIDR(s)
	require.NoError(t, err, "test fixture must be a valid CIDR")
	return ipnet
}

// newSysOpsWithLocalSubnets builds a SysOps whose local subnet cache is pinned, so the
// tests never depend on the addresses of the machine running them.
func newSysOpsWithLocalSubnets(t *testing.T, subnets ...*net.IPNet) *SysOps {
	t.Helper()

	wgNetwork := netip.MustParsePrefix("100.64.0.0/16")
	sysOps := &SysOps{
		wgInterface: &mockWGIface{
			address: wgaddr.Address{
				IP:      netip.MustParseAddr("100.64.0.1"),
				Network: wgNetwork,
			},
			name: "wt0",
		},
		notifier: &notifier.Notifier{},
	}

	sysOps.localSubnetsCache = subnets
	sysOps.localSubnetsCacheTime = time.Now()

	return sysOps
}

func TestSysOps_localSubnetOverlap(t *testing.T) {
	local := []*net.IPNet{
		mustIPNet(t, "192.168.1.0/24"),
		mustIPNet(t, "2001:db8:1::/64"),
	}

	tests := []struct {
		name        string
		prefix      string
		wantOverlap bool
		wantSubnet  string
	}{
		{
			name:        "identical v4 subnet",
			prefix:      "192.168.1.0/24",
			wantOverlap: true,
			wantSubnet:  "192.168.1.0/24",
		},
		{
			name:        "host route inside local subnet",
			prefix:      "192.168.1.10/32",
			wantOverlap: true,
			wantSubnet:  "192.168.1.0/24",
		},
		{
			name:        "more specific subnet inside local subnet",
			prefix:      "192.168.1.0/25",
			wantOverlap: true,
			wantSubnet:  "192.168.1.0/24",
		},
		{
			// Longest-prefix match keeps the local /24 on its own link, so the overlay must
			// still carry the rest of the /16 rather than losing the whole route.
			name:        "supernet containing local subnet stays routed",
			prefix:      "192.168.0.0/16",
			wantOverlap: false,
		},
		{
			// The supernet shares its network address with the local subnet here, which must
			// not be mistaken for the prefix sitting inside it.
			name:        "supernet sharing the local network address stays routed",
			prefix:      "192.168.1.0/23",
			wantOverlap: false,
		},
		{
			name:        "adjacent subnet is routable",
			prefix:      "192.168.2.0/24",
			wantOverlap: false,
		},
		{
			name:        "unrelated subnet is routable",
			prefix:      "10.10.0.0/16",
			wantOverlap: false,
		},
		{
			name:        "default route is exempt",
			prefix:      "0.0.0.0/0",
			wantOverlap: false,
		},
		{
			name:        "v6 default route is exempt",
			prefix:      "::/0",
			wantOverlap: false,
		},
		{
			name:        "v6 host route inside local subnet",
			prefix:      "2001:db8:1::5/128",
			wantOverlap: true,
			wantSubnet:  "2001:db8:1::/64",
		},
		{
			name:        "v6 subnet outside local subnet",
			prefix:      "2001:db8:2::/64",
			wantOverlap: false,
		},
		{
			name:        "v6 supernet containing local subnet stays routed",
			prefix:      "2001:db8:1::/48",
			wantOverlap: false,
		},
		{
			// Overlapping families must never be compared against each other.
			name:        "v6 prefix against v4 local subnet",
			prefix:      "::ffff:192.168.1.0/120",
			wantOverlap: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sysOps := newSysOpsWithLocalSubnets(t, local...)

			subnet, ok := sysOps.localSubnetOverlap(netip.MustParsePrefix(tt.prefix))
			assert.Equal(t, tt.wantOverlap, ok, "overlap verdict for %s", tt.prefix)
			if !tt.wantOverlap {
				assert.Nil(t, subnet, "no subnet should be reported when there is no overlap")
				return
			}
			require.NotNil(t, subnet, "an overlapping subnet must be reported")
			assert.Equal(t, tt.wantSubnet, subnet.String(), "reported subnet for %s", tt.prefix)
		})
	}
}

// A v4 address reported with a 16-byte mask must still compare as IPv4.
func TestSysOps_localSubnetOverlapV4MappedSubnet(t *testing.T) {
	mapped := &net.IPNet{
		IP:   net.ParseIP("192.168.5.0"),
		Mask: net.CIDRMask(96+24, 128),
	}
	sysOps := newSysOpsWithLocalSubnets(t, mapped)

	_, ok := sysOps.localSubnetOverlap(netip.MustParsePrefix("192.168.5.7/32"))
	assert.True(t, ok, "v4-mapped local subnet should match a v4 prefix inside it")

	_, ok = sysOps.localSubnetOverlap(netip.MustParsePrefix("192.168.6.0/24"))
	assert.False(t, ok, "v4-mapped local subnet should not match an unrelated v4 prefix")
}

func TestSysOps_AddVPNRouteSkipsLocalOverlap(t *testing.T) {
	sysOps := newSysOpsWithLocalSubnets(t, mustIPNet(t, "192.168.1.0/24"))

	err := sysOps.AddVPNRoute(netip.MustParsePrefix("192.168.1.10/32"), &net.Interface{Index: 1, Name: "wt0"})
	assert.True(t, errors.Is(err, refcounter.ErrIgnore), "overlapping route must be ignored, got %v", err)
}

func TestSysOps_skipLocalInterface(t *testing.T) {
	sysOps := newSysOpsWithLocalSubnets(t)

	tests := []struct {
		name string
		intf net.Interface
		want bool
	}{
		{
			name: "up physical interface is used",
			intf: net.Interface{Name: "eth0", Flags: net.FlagUp},
			want: false,
		},
		{
			name: "down interface is skipped",
			intf: net.Interface{Name: "eth1"},
			want: true,
		},
		{
			name: "loopback is skipped",
			intf: net.Interface{Name: "lo", Flags: net.FlagUp | net.FlagLoopback},
			want: true,
		},
		{
			name: "overlay interface is skipped",
			intf: net.Interface{Name: "wt0", Flags: net.FlagUp},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sysOps.skipLocalInterface(tt.intf), "skip verdict for %s", tt.intf.Name)
		})
	}
}

func TestSysOps_skipLocalSubnet(t *testing.T) {
	sysOps := newSysOpsWithLocalSubnets(t)

	tests := []struct {
		name  string
		ipnet *net.IPNet
		want  bool
	}{
		{
			name:  "lan subnet is kept",
			ipnet: &net.IPNet{IP: net.ParseIP("192.168.1.20"), Mask: net.CIDRMask(24, 32)},
			want:  false,
		},
		{
			// A host behind CGNAT has a physical subnet inside the default 100.64.0.0/10
			// overlay pool. It must stay in the cache, or a VPN route could shadow it.
			// The overlay's own addresses are excluded by interface, not by pool membership.
			name:  "physical subnet overlapping the overlay pool is kept",
			ipnet: &net.IPNet{IP: net.ParseIP("100.64.0.1"), Mask: net.CIDRMask(16, 32)},
			want:  false,
		},
		{
			name:  "link local v4 is skipped",
			ipnet: &net.IPNet{IP: net.ParseIP("169.254.3.4"), Mask: net.CIDRMask(16, 32)},
			want:  true,
		},
		{
			name:  "link local v6 is skipped",
			ipnet: &net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
			want:  true,
		},
		{
			name:  "loopback address is skipped",
			ipnet: &net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
			want:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sysOps.skipLocalSubnet(tt.ipnet), "skip verdict for %s", tt.ipnet)
		})
	}
}

func TestIPNetToPrefix(t *testing.T) {
	tests := []struct {
		name   string
		ipnet  *net.IPNet
		want   string
		wantOK bool
	}{
		{
			name:   "v4 subnet",
			ipnet:  &net.IPNet{IP: net.ParseIP("192.168.1.20"), Mask: net.CIDRMask(24, 32)},
			want:   "192.168.1.0/24",
			wantOK: true,
		},
		{
			name:   "v4 subnet with v6 sized mask",
			ipnet:  &net.IPNet{IP: net.ParseIP("192.168.1.20"), Mask: net.CIDRMask(96+24, 128)},
			want:   "192.168.1.0/24",
			wantOK: true,
		},
		{
			name:   "v6 subnet",
			ipnet:  &net.IPNet{IP: net.ParseIP("2001:db8::5"), Mask: net.CIDRMask(64, 128)},
			want:   "2001:db8::/64",
			wantOK: true,
		},
		{
			name:   "nil subnet",
			ipnet:  nil,
			wantOK: false,
		},
		{
			name:   "non contiguous mask",
			ipnet:  &net.IPNet{IP: net.ParseIP("192.168.1.20"), Mask: net.IPMask{255, 0, 255, 0}},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, ok := ipNetToPrefix(tt.ipnet)
			require.Equal(t, tt.wantOK, ok, "conversion verdict")
			if !tt.wantOK {
				return
			}
			assert.Equal(t, tt.want, prefix.String(), "converted prefix")
		})
	}
}
