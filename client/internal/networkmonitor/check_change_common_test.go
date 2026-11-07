//go:build dragonfly || freebsd || netbsd || openbsd || darwin

package networkmonitor

import (
	"net"
	"net/netip"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

func TestDefaultRouteChanged(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		family := "ipv4"
		gateway := netip.MustParseAddr("192.0.2.1")
		var dst, gw, mask route.Addr
		dst = &route.Inet4Addr{}
		gw = &route.Inet4Addr{IP: gateway.As4()}
		mask = &route.Inet4Addr{}
		if ipv6 {
			family = "ipv6"
			gateway = netip.MustParseAddr("2001:db8::1")
			dst = &route.Inet6Addr{}
			gw = &route.Inet6Addr{IP: gateway.As16()}
			mask = &route.Inet6Addr{}
		}
		t.Run(family, func(t *testing.T) {
			for _, tc := range []struct {
				name       string
				msgType    int
				flags      int
				mismatch   bool
				nondefault bool
				want       bool
			}{
				{name: "scoped delete", msgType: unix.RTM_DELETE, flags: unix.RTF_GATEWAY | monitorScopedFlag(), want: runtime.GOOS != "darwin"},
				{name: "marked scoped delete", msgType: unix.RTM_DELETE, flags: unix.RTF_GATEWAY | unix.RTF_PROTO1 | monitorScopedFlag(), want: runtime.GOOS != "darwin"},
				{name: "delete without up", msgType: unix.RTM_DELETE, flags: unix.RTF_GATEWAY, want: true},
				{name: "delete with up", msgType: unix.RTM_DELETE, flags: unix.RTF_GATEWAY | unix.RTF_UP, want: true},
				{name: "unrelated gateway", msgType: unix.RTM_DELETE, mismatch: true},
				{name: "nondefault delete", msgType: unix.RTM_DELETE, nondefault: true},
				{name: "scoped add", msgType: unix.RTM_ADD, flags: unix.RTF_GATEWAY | unix.RTF_UP | monitorScopedFlag(), want: runtime.GOOS != "darwin"},
				{name: "unscoped replacement", msgType: unix.RTM_ADD, flags: unix.RTF_GATEWAY | unix.RTF_UP, want: true},
				{name: "nondefault add", msgType: unix.RTM_ADD, flags: unix.RTF_GATEWAY | unix.RTF_UP, nondefault: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					msgMask := mask
					if tc.nondefault {
						if ipv6 {
							msgMask = &route.Inet6Addr{IP: [16]byte{255, 255, 255, 255, 255, 255, 255, 255}}
						} else {
							msgMask = &route.Inet4Addr{IP: [4]byte{255, 255, 255, 0}}
						}
					}
					msg := &route.RouteMessage{Version: unix.RTM_VERSION, Type: tc.msgType, Flags: tc.flags, Index: 18, Addrs: []route.Addr{dst, gw, msgMask}}
					buf, err := msg.Marshal()
					require.NoError(t, err)
					r, flags, err := parseRouteMessage(buf)
					require.NoError(t, err)
					require.Nil(t, r.Interface, "IP gateways decode without an interface")
					next := systemops.Nexthop{IP: gateway, Intf: &net.Interface{Index: 18}}
					if tc.mismatch {
						next.IP = netip.MustParseAddr("192.0.2.254")
					}
					var v4, v6 systemops.Nexthop
					if ipv6 {
						v6 = next
					} else {
						v4 = next
					}
					assert.Equal(t, tc.want, defaultRouteChanged(tc.msgType, r, flags, v4, v6), "default route change classification")
				})
			}
		})
	}
}
