package anonymize_test

import (
	"net/netip"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/anonymize"
)

func TestAnonymizeIP(t *testing.T) {
	startIPv4 := netip.MustParseAddr("198.51.100.0")
	startIPv6 := netip.MustParseAddr("100::")
	anonymizer := anonymize.NewAnonymizer(startIPv4, startIPv6)

	tests := []struct {
		name   string
		ip     string
		expect string
	}{
		{"Well known", "8.8.8.8", "8.8.8.8"},
		{"First Public IPv4", "1.2.3.4", "198.51.100.0"},
		{"Second Public IPv4", "4.3.2.1", "198.51.100.1"},
		{"Repeated IPv4", "1.2.3.4", "198.51.100.0"},
		{"Private IPv4", "192.168.1.1", "192.168.1.1"},
		{"First Public IPv6", "2607:f8b0:4005:805::200e", "100::"},
		{"Second Public IPv6", "a::b", "100::1"},
		{"Repeated IPv6", "2607:f8b0:4005:805::200e", "100::"},
		{"Private IPv6", "fe80::1", "fe80::1"},
		{"In Range IPv4", "198.51.100.2", "198.51.100.2"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ip := netip.MustParseAddr(tc.ip)
			anonymizedIP := anonymizer.AnonymizeIP(ip)
			if anonymizedIP.String() != tc.expect {
				t.Errorf("%s: expected %s, got %s", tc.name, tc.expect, anonymizedIP)
			}
		})
	}
}