package peer

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestP2PPathLost(t *testing.T) {
	onHost := map[netip.Addr]bool{
		netip.MustParseAddr("10.132.0.3"):  true,
		netip.MustParseAddr("2001:db8::7"): true,
	}
	exists := func(a netip.Addr) bool { return onHost[a] }

	tests := []struct {
		name     string
		candType string
		endpoint string
		want     bool
	}{
		// The old interface is still up, as with a cable plugged while Wi-Fi
		// stays connected: the direct path keeps working.
		{name: "host candidate whose address is still on the host", candType: "host", endpoint: "10.132.0.3:51820", want: false},
		{name: "host candidate on IPv6 still on the host", candType: "host", endpoint: "[2001:db8::7]:51820", want: false},
		// Wi-Fi off or a new DHCP lease: the local end of the path is gone.
		{name: "host candidate whose address is gone", candType: "host", endpoint: "192.168.1.20:51820", want: true},
		// Behind NAT or TURN the path depends on the old network's mapping.
		{name: "server reflexive candidate", candType: "srflx", endpoint: "203.0.113.5:40000", want: true},
		{name: "peer reflexive candidate", candType: "prflx", endpoint: "203.0.113.5:40000", want: true},
		{name: "relay candidate", candType: "relay", endpoint: "198.51.100.9:3478", want: true},
		{name: "unparsable endpoint is treated as lost", candType: "host", endpoint: "not-an-endpoint", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, p2pPathLost(tt.candType, tt.endpoint, exists), "path lost verdict")
		})
	}
}
