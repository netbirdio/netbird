package networkmonitor

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

func TestClassify(t *testing.T) {
	wifi := &net.Interface{Index: 2, Name: "en0"}
	cable := &net.Interface{Index: 5, Name: "en5"}
	home := netip.MustParseAddr("192.168.1.1")
	office := netip.MustParseAddr("10.0.0.1")
	v6gw := netip.MustParseAddr("fe80::1")

	tests := []struct {
		name   string
		before NextHops
		after  NextHops
		want   ChangeKind
	}{
		{
			name:   "same next hop, as after a flap or a wake-up on the same network",
			before: NextHops{V4: systemops.Nexthop{IP: home, Intf: wifi}},
			after:  NextHops{V4: systemops.Nexthop{IP: home, Intf: wifi}},
			want:   ChangeNone,
		},
		{
			name:   "same Wi-Fi adapter joins another network",
			before: NextHops{V4: systemops.Nexthop{IP: home, Intf: wifi}},
			after:  NextHops{V4: systemops.Nexthop{IP: office, Intf: wifi}},
			want:   ChangeGateway,
		},
		{
			name:   "cable plugged in on the same LAN keeps the gateway but moves the interface",
			before: NextHops{V4: systemops.Nexthop{IP: home, Intf: wifi}},
			after:  NextHops{V4: systemops.Nexthop{IP: home, Intf: cable}},
			want:   ChangeInterface,
		},
		{
			name:   "default route gone counts as an interface change",
			before: NextHops{V4: systemops.Nexthop{IP: home, Intf: wifi}},
			after:  NextHops{},
			want:   ChangeInterface,
		},
		{
			name:   "default route appears after having none",
			before: NextHops{},
			after:  NextHops{V4: systemops.Nexthop{IP: home, Intf: wifi}},
			want:   ChangeInterface,
		},
		{
			name: "strongest family wins: v4 gateway change, v6 interface change",
			before: NextHops{
				V4: systemops.Nexthop{IP: home, Intf: wifi},
				V6: systemops.Nexthop{IP: v6gw, Intf: wifi},
			},
			after: NextHops{
				V4: systemops.Nexthop{IP: office, Intf: wifi},
				V6: systemops.Nexthop{IP: v6gw, Intf: cable},
			},
			want: ChangeInterface,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, classify(tt.before, tt.after), "change kind")
		})
	}
}
