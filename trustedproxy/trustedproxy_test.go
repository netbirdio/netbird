package trustedproxy

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    []netip.Prefix
		wantErr bool
	}{
		{
			name: "empty string returns empty list",
			raw:  "",
			want: nil,
		},
		{
			name: "single CIDR",
			raw:  "10.0.0.0/8",
			want: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		},
		{
			name: "single bare IPv4",
			raw:  "1.2.3.4",
			want: []netip.Prefix{netip.MustParsePrefix("1.2.3.4/32")},
		},
		{
			name: "single bare IPv6",
			raw:  "::1",
			want: []netip.Prefix{netip.MustParsePrefix("::1/128")},
		},
		{
			name: "comma-separated CIDRs",
			raw:  "10.0.0.0/8, 192.168.1.0/24",
			want: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("192.168.1.0/24"),
			},
		},
		{
			name: "mixed CIDRs and bare IPs",
			raw:  "10.0.0.0/8, 1.2.3.4, fd00::/8",
			want: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("1.2.3.4/32"),
				netip.MustParsePrefix("fd00::/8"),
			},
		},
		{
			name: "whitespace around entries",
			raw:  "  10.0.0.0/8 , 192.168.0.0/16  ",
			want: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("192.168.0.0/16"),
			},
		},
		{
			name: "trailing comma produces no extra entry",
			raw:  "10.0.0.0/8,",
			want: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		},
		{
			name:    "invalid entry",
			raw:     "not-an-ip",
			wantErr: true,
		},
		{
			name:    "partially invalid",
			raw:     "10.0.0.0/8, garbage",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got.prefixes)
		})
	}
}

func TestListIsTrusted(t *testing.T) {
	list, err := Parse("10.0.0.0/8, 192.168.1.0/24, fd00::/8")
	require.NoError(t, err)

	tests := []struct {
		name string
		addr string
		list *List
		want bool
	}{
		{"nil list", "10.0.0.1", nil, false},
		{"empty list", "10.0.0.1", &List{}, false},
		{"IP within /8 prefix", "10.1.2.3", list, true},
		{"IP within /24 prefix", "192.168.1.100", list, true},
		{"IP outside all prefixes", "203.0.113.50", list, false},
		{"boundary IP just outside prefix", "192.168.2.1", list, false},
		{"unparsable IP", "not-an-ip", list, false},
		{"IPv6 in trusted range", "fd00::1", list, true},
		{"IPv6 outside range", "2001:db8::1", list, false},
		{"empty string", "", list, false},
		{"host:port within prefix", "10.1.2.3:9999", list, true},
		{"host:port outside prefix", "203.0.113.50:9999", list, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.list.IsTrusted(tt.addr))
		})
	}
}

func TestListResolveClientIP(t *testing.T) {
	trusted, err := Parse("10.0.0.0/8, 172.16.0.0/12")
	require.NoError(t, err)

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		list       *List
		want       netip.Addr
	}{
		{
			name:       "empty list returns RemoteAddr",
			remoteAddr: "203.0.113.50:9999",
			xff:        "1.2.3.4",
			list:       &List{},
			want:       netip.MustParseAddr("203.0.113.50"),
		},
		{
			name:       "nil list returns RemoteAddr",
			remoteAddr: "203.0.113.50:9999",
			xff:        "1.2.3.4",
			list:       nil,
			want:       netip.MustParseAddr("203.0.113.50"),
		},
		{
			name:       "untrusted RemoteAddr ignores XFF",
			remoteAddr: "203.0.113.50:9999",
			xff:        "1.2.3.4, 10.0.0.1",
			list:       trusted,
			want:       netip.MustParseAddr("203.0.113.50"),
		},
		{
			name:       "trusted RemoteAddr with single client in XFF",
			remoteAddr: "10.0.0.1:5000",
			xff:        "203.0.113.50",
			list:       trusted,
			want:       netip.MustParseAddr("203.0.113.50"),
		},
		{
			name:       "trusted RemoteAddr walks past trusted entries in XFF",
			remoteAddr: "10.0.0.1:5000",
			xff:        "203.0.113.50, 10.0.0.2, 172.16.0.5",
			list:       trusted,
			want:       netip.MustParseAddr("203.0.113.50"),
		},
		{
			name:       "trusted RemoteAddr with empty XFF falls back to RemoteAddr",
			remoteAddr: "10.0.0.1:5000",
			xff:        "",
			list:       trusted,
			want:       netip.MustParseAddr("10.0.0.1"),
		},
		{
			name:       "all XFF IPs trusted returns leftmost",
			remoteAddr: "10.0.0.1:5000",
			xff:        "10.0.0.2, 172.16.0.1, 10.0.0.3",
			list:       trusted,
			want:       netip.MustParseAddr("10.0.0.2"),
		},
		{
			name:       "XFF with whitespace",
			remoteAddr: "10.0.0.1:5000",
			xff:        " 203.0.113.50 , 10.0.0.2 ",
			list:       trusted,
			want:       netip.MustParseAddr("203.0.113.50"),
		},
		{
			name:       "XFF with empty segments",
			remoteAddr: "10.0.0.1:5000",
			xff:        "203.0.113.50,,10.0.0.2",
			list:       trusted,
			want:       netip.MustParseAddr("203.0.113.50"),
		},
		{
			name:       "multi-hop with mixed trust",
			remoteAddr: "10.0.0.1:5000",
			xff:        "8.8.8.8, 203.0.113.50, 172.16.0.1",
			list:       trusted,
			want:       netip.MustParseAddr("203.0.113.50"),
		},
		{
			name:       "RemoteAddr without port",
			remoteAddr: "10.0.0.1",
			xff:        "203.0.113.50",
			list:       trusted,
			want:       netip.MustParseAddr("203.0.113.50"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.list.ResolveClientIP(tt.remoteAddr, tt.xff))
		})
	}
}
