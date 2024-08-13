package server

import (
	"github.com/stretchr/testify/require"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewNetwork(t *testing.T) {
	network := NewNetwork(true)

	// generated net should be a subnet of a larger 100.64.0.0/10 net
	ipNet := net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.IPMask{255, 192, 0, 0}}
	assert.True(t, ipNet.Contains(network.Net.IP))

	// generated IPv6 net should be a subnet of the fd00:b14d::/32 prefix.
	_, ipNet6, err := net.ParseCIDR("fd00:b14d::/32")
	require.NoError(t, err, "unable to parse IPv6 prefix")
	assert.True(t, ipNet6.Contains(network.Net6.IP))
	// IPv6 prefix should be of size /64
	ones, _ := network.Net6.Mask.Size()
	assert.Equal(t, ones, 64)
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

func TestAllocatePeerIP6(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("2001:db8:abcd:1234::/64")
	require.NoError(t, err, "unable to parse IPv6 prefix")
	var ips []net.IP
	// Yeah, we better not check all 2^64 possible addresses, just generating a bunch of addresses should hopefully
	// reveal any possible bugs in the RNG.
	for i := 0; i < 252; i++ {
		ip, err := AllocatePeerIP6(*ipNet, ips)
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
