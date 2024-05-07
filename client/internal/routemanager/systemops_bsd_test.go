//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package routemanager

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/net/route"
)

func TestBits(t *testing.T) {
	tests := []struct {
		name    string
		addr    route.Addr
		want    int
		wantErr bool
	}{
		{
			name: "IPv4 all ones",
			addr: &route.Inet4Addr{IP: [4]byte{255, 255, 255, 255}},
			want: 32,
		},
		{
			name: "IPv4 normal mask",
			addr: &route.Inet4Addr{IP: [4]byte{255, 255, 255, 0}},
			want: 24,
		},
		{
			name: "IPv6 all ones",
			addr: &route.Inet6Addr{IP: [16]byte{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255}},
			want: 128,
		},
		{
			name: "IPv6 normal mask",
			addr: &route.Inet6Addr{IP: [16]byte{255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0}},
			want: 64,
		},
		{
			name:    "Unsupported type",
			addr:    &route.LinkAddr{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ones(tt.addr)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
