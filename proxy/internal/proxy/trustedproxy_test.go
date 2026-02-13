package proxy

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsTrustedProxy(t *testing.T) {
	trusted := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("fd00::/8"),
	}

	tests := []struct {
		name    string
		ip      string
		trusted []netip.Prefix
		want    bool
	}{
		{"empty trusted list", "10.0.0.1", nil, false},
		{"IP within /8 prefix", "10.1.2.3", trusted, true},
		{"IP within /24 prefix", "192.168.1.100", trusted, true},
		{"IP outside all prefixes", "203.0.113.50", trusted, false},
		{"boundary IP just outside prefix", "192.168.2.1", trusted, false},
		{"unparsable IP", "not-an-ip", trusted, false},
		{"IPv6 in trusted range", "fd00::1", trusted, true},
		{"IPv6 outside range", "2001:db8::1", trusted, false},
		{"empty string", "", trusted, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsTrustedProxy(tt.ip, tt.trusted))
		})
	}
}

func TestResolveClientIP(t *testing.T) {
	trusted := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
	}

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		trusted    []netip.Prefix
		want       string
	}{
		{
			name:       "empty trusted list returns RemoteAddr",
			remoteAddr: "203.0.113.50:9999",
			xff:        "1.2.3.4",
			trusted:    nil,
			want:       "203.0.113.50",
		},
		{
			name:       "untrusted RemoteAddr ignores XFF",
			remoteAddr: "203.0.113.50:9999",
			xff:        "1.2.3.4, 10.0.0.1",
			trusted:    trusted,
			want:       "203.0.113.50",
		},
		{
			name:       "trusted RemoteAddr with single client in XFF",
			remoteAddr: "10.0.0.1:5000",
			xff:        "203.0.113.50",
			trusted:    trusted,
			want:       "203.0.113.50",
		},
		{
			name:       "trusted RemoteAddr walks past trusted entries in XFF",
			remoteAddr: "10.0.0.1:5000",
			xff:        "203.0.113.50, 10.0.0.2, 172.16.0.5",
			trusted:    trusted,
			want:       "203.0.113.50",
		},
		{
			name:       "trusted RemoteAddr with empty XFF falls back to RemoteAddr",
			remoteAddr: "10.0.0.1:5000",
			xff:        "",
			trusted:    trusted,
			want:       "10.0.0.1",
		},
		{
			name:       "all XFF IPs trusted returns leftmost",
			remoteAddr: "10.0.0.1:5000",
			xff:        "10.0.0.2, 172.16.0.1, 10.0.0.3",
			trusted:    trusted,
			want:       "10.0.0.2",
		},
		{
			name:       "XFF with whitespace",
			remoteAddr: "10.0.0.1:5000",
			xff:        " 203.0.113.50 , 10.0.0.2 ",
			trusted:    trusted,
			want:       "203.0.113.50",
		},
		{
			name:       "XFF with empty segments",
			remoteAddr: "10.0.0.1:5000",
			xff:        "203.0.113.50,,10.0.0.2",
			trusted:    trusted,
			want:       "203.0.113.50",
		},
		{
			name:       "multi-hop with mixed trust",
			remoteAddr: "10.0.0.1:5000",
			xff:        "8.8.8.8, 203.0.113.50, 172.16.0.1",
			trusted:    trusted,
			want:       "203.0.113.50",
		},
		{
			name:       "RemoteAddr without port",
			remoteAddr: "10.0.0.1",
			xff:        "203.0.113.50",
			trusted:    trusted,
			want:       "203.0.113.50",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ResolveClientIP(tt.remoteAddr, tt.xff, tt.trusted))
		})
	}
}
