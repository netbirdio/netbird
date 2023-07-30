package dns

import (
	"net"
	"testing"
)

func TestGetLastIPFromNetwork(t *testing.T) {
	tests := []struct {
		addr string
		ip   string
	}{
		{"2001:db8::/32", "2001:db8:ffff:ffff:ffff:ffff:ffff:fffe"},
		{"192.168.0.0/30", "192.168.0.2"},
		{"192.168.0.0/16", "192.168.255.254"},
		{"192.168.0.0/24", "192.168.0.254"},
	}

	for _, tt := range tests {
		_, ipnet, err := net.ParseCIDR(tt.addr)
		if err != nil {
			t.Errorf("Error parsing CIDR: %v", err)
			return
		}

		lastIP := getLastIPFromNetwork(ipnet, 1)
		if lastIP != tt.ip {
			t.Errorf("wrong IP address, expected %s: got %s", tt.ip, lastIP)
		}
	}
}
