package internal

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/system"
)

func TestNetworkAddressesEqual(t *testing.T) {
	tests := []struct {
		name string
		a    []system.NetworkAddress
		b    []system.NetworkAddress
		want bool
	}{
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			want: true,
		},
		{
			name: "both empty",
			a:    []system.NetworkAddress{},
			b:    []system.NetworkAddress{},
			want: true,
		},
		{
			name: "nil vs empty",
			a:    nil,
			b:    []system.NetworkAddress{},
			want: true,
		},
		{
			name: "same addresses same order",
			a: []system.NetworkAddress{
				{NetIP: netip.MustParsePrefix("192.168.1.10/24")},
				{NetIP: netip.MustParsePrefix("10.0.0.1/8")},
			},
			b: []system.NetworkAddress{
				{NetIP: netip.MustParsePrefix("192.168.1.10/24")},
				{NetIP: netip.MustParsePrefix("10.0.0.1/8")},
			},
			want: true,
		},
		{
			name: "same addresses different order",
			a: []system.NetworkAddress{
				{NetIP: netip.MustParsePrefix("10.0.0.1/8")},
				{NetIP: netip.MustParsePrefix("192.168.1.10/24")},
			},
			b: []system.NetworkAddress{
				{NetIP: netip.MustParsePrefix("192.168.1.10/24")},
				{NetIP: netip.MustParsePrefix("10.0.0.1/8")},
			},
			want: true,
		},
		{
			name: "different lengths",
			a: []system.NetworkAddress{
				{NetIP: netip.MustParsePrefix("192.168.1.10/24")},
			},
			b: []system.NetworkAddress{
				{NetIP: netip.MustParsePrefix("192.168.1.10/24")},
				{NetIP: netip.MustParsePrefix("10.0.0.1/8")},
			},
			want: false,
		},
		{
			name: "different addresses",
			a: []system.NetworkAddress{
				{NetIP: netip.MustParsePrefix("192.168.1.10/24")},
			},
			b: []system.NetworkAddress{
				{NetIP: netip.MustParsePrefix("172.16.0.1/12")},
			},
			want: false,
		},
		{
			name: "wifi to mobile switch",
			a: []system.NetworkAddress{
				{NetIP: netip.MustParsePrefix("192.168.91.167/24")},
				{NetIP: netip.MustParsePrefix("100.87.143.60/16")},
			},
			b: []system.NetworkAddress{
				{NetIP: netip.MustParsePrefix("93.111.154.63/24")},
				{NetIP: netip.MustParsePrefix("100.87.143.60/16")},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := networkAddressesEqual(tt.a, tt.b)
			assert.Equal(t, tt.want, got)
		})
	}
}
