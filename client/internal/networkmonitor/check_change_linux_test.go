//go:build !android

package networkmonitor

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsDefaultRoute(t *testing.T) {
	mustCIDR := func(s string) *net.IPNet {
		t.Helper()
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatalf("parse %s: %v", s, err)
		}
		return n
	}

	tests := []struct {
		name string
		dst  *net.IPNet
		want bool
	}{
		// netlink before v1.3 left Dst nil for the default route.
		{name: "nil dst", dst: nil, want: true},
		// netlink v1.3 reports the default route with an explicit zero-length prefix.
		{name: "v4 default", dst: mustCIDR("0.0.0.0/0"), want: true},
		{name: "v6 default", dst: mustCIDR("::/0"), want: true},
		// The exit node split routes and ordinary prefixes are not defaults.
		{name: "v4 split half", dst: mustCIDR("0.0.0.0/1"), want: false},
		{name: "v4 subnet", dst: mustCIDR("10.0.0.0/8"), want: false},
		{name: "v4 host", dst: mustCIDR("1.1.1.1/32"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isDefaultRoute(tt.dst), "default route detection")
		})
	}
}
