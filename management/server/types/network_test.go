package types

import (
	"net"
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
	ipNet := net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.IPMask{255, 255, 255, 0}}
	var ips []net.IP
	for i := 0; i < 252; i++ {
		ip, err := AllocatePeerIP(ipNet, ips)
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
	// Test /27 network (10.0.0.0/27) - should only have 30 usable IPs (10.0.0.1 to 10.0.0.30)
	ipNet := net.IPNet{IP: net.ParseIP("10.0.0.0"), Mask: net.IPMask{255, 255, 255, 224}}
	var ips []net.IP

	// Allocate all available IPs in the /27 network
	for i := 0; i < 30; i++ {
		ip, err := AllocatePeerIP(ipNet, ips)
		if err != nil {
			t.Fatal(err)
		}

		// Verify IP is within the correct range
		if !ipNet.Contains(ip) {
			t.Errorf("allocated IP %s is not within network %s", ip.String(), ipNet.String())
		}

		ips = append(ips, ip)
	}

	assert.Len(t, ips, 30)

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
	_, err := AllocatePeerIP(ipNet, ips)
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
		{"/30 network", "192.168.1.0/30", 2},   // 4 total - 2 reserved = 2 usable
		{"/29 network", "192.168.1.0/29", 6},   // 8 total - 2 reserved = 6 usable
		{"/28 network", "192.168.1.0/28", 14},  // 16 total - 2 reserved = 14 usable
		{"/27 network", "192.168.1.0/27", 30},  // 32 total - 2 reserved = 30 usable
		{"/26 network", "192.168.1.0/26", 62},  // 64 total - 2 reserved = 62 usable
		{"/25 network", "192.168.1.0/25", 126}, // 128 total - 2 reserved = 126 usable
		{"/16 network", "10.0.0.0/16", 65534},  // 65536 total - 2 reserved = 65534 usable
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, ipNet, err := net.ParseCIDR(tc.cidr)
			require.NoError(t, err)

			var ips []net.IP

			// For larger networks, test only a subset to avoid long test runs
			testCount := tc.expectedUsable
			if testCount > 1000 {
				testCount = 1000
			}

			// Allocate IPs and verify they're within the correct range
			for i := 0; i < testCount; i++ {
				ip, err := AllocatePeerIP(*ipNet, ips)
				require.NoError(t, err, "failed to allocate IP %d", i)

				// Verify IP is within the correct range
				assert.True(t, ipNet.Contains(ip), "allocated IP %s is not within network %s", ip.String(), ipNet.String())

				// Verify IP is not network or broadcast address
				networkIP := ipNet.IP.Mask(ipNet.Mask)
				ones, bits := ipNet.Mask.Size()
				hostBits := bits - ones
				broadcastInt := uint32(ipToUint32(networkIP)) + (1 << hostBits) - 1
				broadcastIP := uint32ToIP(broadcastInt)

				assert.False(t, ip.Equal(networkIP), "allocated network address %s", ip.String())
				assert.False(t, ip.Equal(broadcastIP), "allocated broadcast address %s", ip.String())

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
