package server

import (
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestAllocatePeerIP(t *testing.T) {

	ipNet := net.IPNet{IP: net.ParseIP("100.64.0.0"), Mask: net.IPMask{255, 255, 255, 0}}
	var ips []net.IP
	for i := 0; i < 253; i++ {
		ip, err := AllocatePeerIP(ipNet, ips)
		if err != nil {
			t.Fatal(err)
		}
		ips = append(ips, ip)
	}

	assert.Len(t, ips, 253)

	uniq := make(map[string]struct{})
	for _, ip := range ips {
		if _, ok := uniq[ip.String()]; !ok {
			uniq[ip.String()] = struct{}{}
		} else {
			t.Errorf("found duplicate IP %s", ip.String())
		}
	}
}
