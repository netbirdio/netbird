package proxy

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTrustedProxies(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    []netip.Prefix
		wantErr bool
	}{
		{
			name: "empty string returns nil",
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
			got, err := ParseTrustedProxies(tt.raw)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
