//go:build !ios

package system

import (
	"net"
	"testing"
)

func mustIPNet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("parse %q: %v", cidr, err)
	}
	ipNet.IP = ip
	return ipNet
}

func TestToNetworkAddress_Filtering(t *testing.T) {
	const mac = "c8:4b:d6:b6:04:ac"

	tests := []struct {
		name string
		cidr string
		want bool
	}{
		{"ipv4 global", "10.65.16.181/23", true},
		{"ipv6 global", "2620:52:0:4110:102d:6a98:ee75:8b92/64", true},
		{"ipv4 loopback", "127.0.0.1/8", false},
		{"ipv6 loopback", "::1/128", false},
		{"ipv6 link-local", "fe80::871:4c25:23d7:2529/64", false},
		{"ipv4 link-local", "169.254.1.2/16", false},
		{"ipv6 multicast", "ff02::1/128", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got := toNetworkAddress(mustIPNet(t, tt.cidr), mac)
			if got != tt.want {
				t.Errorf("toNetworkAddress(%s) ok = %v, want %v", tt.cidr, got, tt.want)
			}
		})
	}
}
