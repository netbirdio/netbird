package server

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewNetwork(t *testing.T) {
	network := NewNetwork(false)

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
