package types

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNetwork(t *testing.T) {
	network := NewNetwork()

	// generated net should be a subnet of a larger 100.64.0.0/10 net
	ipNet := net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.IPMask{255, 192, 0, 0}}
	assert.Equal(t, ipNet.Contains(network.Net.IP), true)
}

func TestAllocatePeerIP(t *testing.T) {
	prefix := netip.MustParsePrefix("100.64.0.0/24")
	var ips []netip.Addr
	for i := 0; i < 252; i++ {
		ip, err := AllocatePeerIP(prefix, ips)
		if err != nil {
			t.Fatal(err)
		}
		ips = append(ips, ip)
	}

	assert.Len(t, ips, 252)

	uniq := make(map[string]struct{})
	for _, ip := range ips {
		if _, ok := uniq[ip.String()]; !ok {
			uniq[ip.String()] = struct{}{}
		} else {
			t.Errorf("found duplicate IP %s", ip.String())
		}
	}
}

func TestAllocatePeerIPSmallSubnet(t *testing.T) {
	// Test /27 network (10.0.0.0/27) - should only have 29 usable IPs (10.0.0.1 to 10.0.0.29)
	prefix := netip.MustParsePrefix("10.0.0.0/27")
	var ips []netip.Addr

	// Allocate all available IPs in the /27 network
	for i := 0; i < 29; i++ {
		ip, err := AllocatePeerIP(prefix, ips)
		if err != nil {
			t.Fatal(err)
		}

		// Verify IP is within the correct range
		if !prefix.Contains(ip) {
			t.Errorf("allocated IP %s is not within network %s", ip.String(), prefix.String())
		}

		ips = append(ips, ip)
	}

	assert.Len(t, ips, 29)

	// Verify all IPs are unique
	uniq := make(map[string]struct{})
	for _, ip := range ips {
		if _, ok := uniq[ip.String()]; !ok {
			uniq[ip.String()] = struct{}{}
		} else {
			t.Errorf("found duplicate IP %s", ip.String())
		}
	}

	// Try to allocate one more IP - should fail as network is full
	_, err := AllocatePeerIP(prefix, ips)
	if err == nil {
		t.Error("expected error when network is full, but got none")
	}
}

func TestAllocatePeerIPVariousCIDRs(t *testing.T) {
	testCases := []struct {
		name           string
		cidr           string
		expectedUsable int
	}{
		{"/30 network", "192.168.1.0/30", 1},   // 4 total - 3 reserved = 1 usable
		{"/29 network", "192.168.1.0/29", 5},   // 8 total - 3 reserved = 5 usable
		{"/28 network", "192.168.1.0/28", 13},  // 16 total - 3 reserved = 13 usable
		{"/27 network", "192.168.1.0/27", 29},  // 32 total - 3 reserved = 29 usable
		{"/26 network", "192.168.1.0/26", 61},  // 64 total - 3 reserved = 61 usable
		{"/25 network", "192.168.1.0/25", 125}, // 128 total - 3 reserved = 125 usable
		{"/16 network", "10.0.0.0/16", 65533},  // 65536 total - 3 reserved = 65533 usable
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			prefix, err := netip.ParsePrefix(tc.cidr)
			require.NoError(t, err)
			prefix = prefix.Masked()

			var ips []netip.Addr

			// For larger networks, test only a subset to avoid long test runs
			testCount := tc.expectedUsable
			if testCount > 1000 {
				testCount = 1000
			}

			// Allocate IPs and verify they're within the correct range
			for i := 0; i < testCount; i++ {
				ip, err := AllocatePeerIP(prefix, ips)
				require.NoError(t, err, "failed to allocate IP %d", i)

				// Verify IP is within the correct range
				assert.True(t, prefix.Contains(ip), "allocated IP %s is not within network %s", ip.String(), prefix.String())

				// Verify IP is not network, DNS resolver or broadcast address
				networkAddr := prefix.Masked().Addr()
				hostBits := 32 - prefix.Bits()
				b := networkAddr.As4()
				baseIP := binary.BigEndian.Uint32(b[:])
				dnsIP := uint32ToIP(baseIP + (1 << hostBits) - 2)
				broadcastIP := uint32ToIP(baseIP + (1 << hostBits) - 1)

				assert.NotEqual(t, networkAddr, ip, "allocated network address %s", ip.String())
				assert.NotEqual(t, dnsIP, ip, "allocated DNS resolver address %s", ip.String())
				assert.NotEqual(t, broadcastIP, ip, "allocated broadcast address %s", ip.String())

				ips = append(ips, ip)
			}

			assert.Len(t, ips, testCount)

			// Verify all IPs are unique
			uniq := make(map[string]struct{})
			for _, ip := range ips {
				ipStr := ip.String()
				assert.NotContains(t, uniq, ipStr, "found duplicate IP %s", ipStr)
				uniq[ipStr] = struct{}{}
			}
		})
	}
}

func TestAllocatePeerIPSkipsDNSResolverIP(t *testing.T) {
	prefix := netip.MustParsePrefix("192.168.1.0/29")
	ips := []netip.Addr{
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("192.168.1.2"),
		netip.MustParseAddr("192.168.1.3"),
		netip.MustParseAddr("192.168.1.4"),
	}

	ip, err := AllocatePeerIP(prefix, ips)
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("192.168.1.5"), ip)

	_, err = AllocatePeerIP(prefix, append(ips, ip))
	assert.Error(t, err, "192.168.1.6 is the DNS resolver address and must not be allocated")
}

func TestAllocateRandomPeerIPSkipsReservedIPs(t *testing.T) {
	for _, cidr := range []string{"192.168.1.0/30", "192.168.1.0/29"} {
		t.Run(cidr, func(t *testing.T) {
			prefix := netip.MustParsePrefix(cidr)
			for i := 0; i < 1000; i++ {
				ip, err := AllocateRandomPeerIP(prefix)
				require.NoError(t, err)
				require.True(t, prefix.Contains(ip), "allocated IP %s is not within network %s", ip, prefix)
				require.False(t, IsReservedPeerIP(prefix, ip), "allocated reserved IP %s", ip)
			}
		})
	}

	ip, err := AllocateRandomPeerIP(netip.MustParsePrefix("192.168.1.0/30"))
	require.NoError(t, err)
	assert.Equal(t, netip.MustParseAddr("192.168.1.1"), ip)
}

func TestIsReservedPeerIP(t *testing.T) {
	prefix := netip.MustParsePrefix("100.64.0.0/24")
	testCases := []struct {
		ip       string
		reserved bool
	}{
		{"100.64.0.0", true},
		{"100.64.0.1", false},
		{"100.64.0.253", false},
		{"100.64.0.254", true},
		{"100.64.0.255", true},
		{"::ffff:100.64.0.254", true},
		{"100.64.1.254", false},
		{"fd12:3456:7890:abcd::1", false},
	}

	for _, tc := range testCases {
		t.Run(tc.ip, func(t *testing.T) {
			assert.Equal(t, tc.reserved, IsReservedPeerIP(prefix, netip.MustParseAddr(tc.ip)))
		})
	}

	smallest := netip.MustParsePrefix("192.168.1.0/30")
	assert.False(t, IsReservedPeerIP(smallest, netip.MustParseAddr("192.168.1.1")))
	assert.True(t, IsReservedPeerIP(smallest, netip.MustParseAddr("192.168.1.2")))
}

func TestAllocateIPv4InvalidPrefixes(t *testing.T) {
	prefixes := []netip.Prefix{
		{},
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("192.168.1.0/31"),
		netip.MustParsePrefix("192.168.1.1/32"),
		netip.MustParsePrefix("fd12:3456:7890:abcd::/64"),
	}

	for _, prefix := range prefixes {
		t.Run(prefix.String(), func(t *testing.T) {
			_, err := AllocatePeerIP(prefix, nil)
			assert.Error(t, err)

			_, err = AllocateRandomPeerIP(prefix)
			assert.Error(t, err)
		})
	}
}

func TestAllocatePeerIPIgnoresNonIPv4TakenIPs(t *testing.T) {
	prefix := netip.MustParsePrefix("192.168.1.0/29")

	ip, err := AllocatePeerIP(prefix, []netip.Addr{netip.MustParseAddr("fd12:3456:7890:abcd::1")})
	require.NoError(t, err)
	assert.True(t, prefix.Contains(ip))
}

func TestGenerateIPs(t *testing.T) {
	ipNet := net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.IPMask{255, 255, 255, 0}}
	ips, ipsLen := generateIPs(&ipNet, map[string]struct{}{"100.64.0.0": {}})
	if ipsLen != 252 {
		t.Errorf("expected 252 ips, got %d", len(ips))
		return
	}
	if ips[len(ips)-1].String() != "100.64.0.253" {
		t.Errorf("expected last ip to be: 100.64.0.253, got %s", ips[len(ips)-1].String())
	}
}

func TestNewNetworkHasIPv6(t *testing.T) {
	network := NewNetwork()

	assert.NotNil(t, network.NetV6.IP, "v6 subnet should be allocated")
	assert.True(t, network.NetV6.IP.To4() == nil, "v6 subnet should be IPv6")
	assert.Equal(t, byte(0xfd), network.NetV6.IP[0], "v6 subnet should be ULA (fd prefix)")

	ones, bits := network.NetV6.Mask.Size()
	assert.Equal(t, 64, ones, "v6 subnet should be /64")
	assert.Equal(t, 128, bits)
}

func TestAllocateIPv6SubnetUniqueness(t *testing.T) {
	seen := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		network := NewNetwork()
		key := network.NetV6.IP.String()
		_, duplicate := seen[key]
		assert.False(t, duplicate, "duplicate v6 subnet: %s", key)
		seen[key] = struct{}{}
	}
}

func TestAllocateRandomPeerIPv6(t *testing.T) {
	prefix := netip.MustParsePrefix("fd12:3456:7890:abcd::/64")

	ip, err := AllocateRandomPeerIPv6(prefix)
	require.NoError(t, err)

	assert.True(t, ip.Is6(), "should be IPv6")
	assert.True(t, prefix.Contains(ip), "should be within subnet")
	// First 8 bytes (network prefix) should match
	b := ip.As16()
	prefixBytes := prefix.Addr().As16()
	assert.Equal(t, prefixBytes[:8], b[:8], "prefix should match")
	// Interface ID should not be all zeros
	allZero := true
	for _, v := range b[8:] {
		if v != 0 {
			allZero = false
			break
		}
	}
	assert.False(t, allZero, "interface ID should not be all zeros")
}

func TestAllocateRandomPeerIPv6_VariousPrefixes(t *testing.T) {
	tests := []struct {
		name   string
		cidr   string
		prefix int
	}{
		{"standard /64", "fd00:1234:5678:abcd::/64", 64},
		{"small /112", "fd00:1234:5678:abcd::/112", 112},
		{"large /48", "fd00:1234::/48", 48},
		{"non-boundary /60", "fd00:1234:5670::/60", 60},
		{"non-boundary /52", "fd00:1230::/52", 52},
		{"minimum /120", "fd00:1234:5678:abcd::100/120", 120},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix, err := netip.ParsePrefix(tt.cidr)
			require.NoError(t, err)
			prefix = prefix.Masked()

			assert.Equal(t, tt.prefix, prefix.Bits())

			for i := 0; i < 50; i++ {
				ip, err := AllocateRandomPeerIPv6(prefix)
				require.NoError(t, err)
				assert.True(t, prefix.Contains(ip), "IP %s should be within %s", ip, prefix)
			}
		})
	}
}

func TestAllocateRandomPeerIPv6_PreservesNetworkBits(t *testing.T) {
	// For a /112, bytes 0-13 should be preserved, only bytes 14-15 should vary
	prefix := netip.MustParsePrefix("fd00:1234:5678:abcd:ef01:2345:6789:0/112")

	prefixBytes := prefix.Addr().As16()
	for i := 0; i < 20; i++ {
		ip, err := AllocateRandomPeerIPv6(prefix)
		require.NoError(t, err)
		// First 14 bytes (112 bits = 14 bytes) must match the network
		b := ip.As16()
		assert.Equal(t, prefixBytes[:14], b[:14], "network bytes should be preserved for /112")
	}
}

func TestAllocateRandomPeerIPv6_NonByteBoundary(t *testing.T) {
	// For a /60, the first 7.5 bytes are network, so byte 7 is partial
	prefix := netip.MustParsePrefix("fd00:1234:5678:abc0::/60")

	prefixBytes := prefix.Addr().As16()
	for i := 0; i < 50; i++ {
		ip, err := AllocateRandomPeerIPv6(prefix)
		require.NoError(t, err)
		b := ip.As16()
		assert.True(t, prefix.Contains(ip), "IP %s should be within %s", ip, prefix)
		// First 7 bytes must match exactly
		assert.Equal(t, prefixBytes[:7], b[:7], "full network bytes should match for /60")
		// Byte 7: top 4 bits (0xc = 1100) must be preserved
		assert.Equal(t, prefixBytes[7]&0xf0, b[7]&0xf0, "partial byte network bits should be preserved for /60")
	}
}
