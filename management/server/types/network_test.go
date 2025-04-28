package types

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewNetwork(t *testing.T) {
	network := NewNetwork()

	// generated net should be a subnet of a larger 100.64.0.0/10 net
	ipNet := net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.IPMask{255, 192, 0, 0}}
	assert.Equal(t, ipNet.Contains(network.Net.IP), true)
}

func TestAllocatePeerIP(t *testing.T) {
	ipNet := net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.IPMask{255, 255, 255, 0}}
	var ips map[string]struct{}
	for i := 0; i < 252; i++ {
		ip, err := AllocatePeerIP(ipNet, ips)
		if err != nil {
			t.Fatal(err)
		}
		ips[ip.String()] = struct{}{}
	}

	assert.Len(t, ips, 252)

	uniq := make(map[string]struct{})
	for ip := range ips {
		if _, ok := uniq[ip]; !ok {
			uniq[ip] = struct{}{}
		} else {
			t.Errorf("found duplicate IP %s", ip)
		}
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

func BenchmarkAllocatePeerIP(b *testing.B) {
	testCase := []struct {
		name       string
		numUsedIPs int
	}{
		{"1000", 1000},
		{"10000", 10000},
		{"30000", 30000},
		{"40000", 40000},
		{"60000", 60000},
	}
	network := NewNetwork()

	for _, tc := range testCase {
		b.Run(tc.name, func(b *testing.B) {
			usedIPs := generateUsedIPs(network.Net, tc.numUsedIPs)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := AllocatePeerIP(network.Net, usedIPs)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func generateUsedIPs(ipNet net.IPNet, numIPs int) map[string]struct{} {
	usedIPs := make(map[string]struct{}, numIPs)
	for i := 0; i < numIPs; i++ {
		ip, err := AllocatePeerIP(ipNet, usedIPs)
		if err != nil {
			return nil
		}
		usedIPs[ip.String()] = struct{}{}
	}
	return usedIPs
}
