package networkmonitor

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/netbirdio/netbird/client/internal/routemanager/systemops"
)

func TestRouteChanged(t *testing.T) {
	tests := []struct {
		name      string
		route     systemops.RouteUpdate
		nexthopv4 systemops.Nexthop
		nexthopv6 systemops.Nexthop
		expected  bool
	}{
		{
			name: "soft interface should be ignored",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteModified,
				Destination: netip.PrefixFrom(netip.IPv4Unspecified(), 0),
				NextHop: systemops.Nexthop{
					IP: netip.MustParseAddr("192.168.1.1"),
					Intf: &net.Interface{
						Name: "ISATAP-Interface", // isSoftInterface checks name
					},
				},
			},
			nexthopv4: systemops.Nexthop{
				IP: netip.MustParseAddr("192.168.1.2"),
			},
			nexthopv6: systemops.Nexthop{
				IP: netip.MustParseAddr("2001:db8::1"),
			},
			expected: false,
		},
		{
			name: "modified route with different v4 nexthop IP should return true",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteModified,
				Destination: netip.PrefixFrom(netip.IPv4Unspecified(), 0),
				NextHop: systemops.Nexthop{
					IP: netip.MustParseAddr("192.168.1.1"),
					Intf: &net.Interface{
						Index: 1, Name: "eth0",
					},
				},
			},
			nexthopv4: systemops.Nexthop{
				IP: netip.MustParseAddr("192.168.1.2"),
				Intf: &net.Interface{
					Index: 1, Name: "eth0",
				},
			},
			nexthopv6: systemops.Nexthop{
				IP: netip.MustParseAddr("2001:db8::1"),
			},
			expected: true,
		},
		{
			name: "modified route with same v4 nexthop (IP and Intf Index) should return false",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteModified,
				Destination: netip.PrefixFrom(netip.IPv4Unspecified(), 0),
				NextHop: systemops.Nexthop{
					IP: netip.MustParseAddr("192.168.1.1"),
					Intf: &net.Interface{
						Index: 1, Name: "eth0",
					},
				},
			},
			nexthopv4: systemops.Nexthop{
				IP: netip.MustParseAddr("192.168.1.1"),
				Intf: &net.Interface{
					Index: 1, Name: "eth0",
				},
			},
			nexthopv6: systemops.Nexthop{
				IP: netip.MustParseAddr("2001:db8::1"),
			},
			expected: false,
		},
		{
			name: "added route with different v6 nexthop IP should return true",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteAdded,
				Destination: netip.PrefixFrom(netip.IPv6Unspecified(), 0),
				NextHop: systemops.Nexthop{
					IP: netip.MustParseAddr("2001:db8::2"),
					Intf: &net.Interface{
						Index: 1, Name: "eth0",
					},
				},
			},
			nexthopv4: systemops.Nexthop{
				IP: netip.MustParseAddr("192.168.1.1"),
			},
			nexthopv6: systemops.Nexthop{
				IP: netip.MustParseAddr("2001:db8::1"),
				Intf: &net.Interface{
					Index: 1, Name: "eth0",
				},
			},
			expected: true,
		},
		{
			name: "added route with same v6 nexthop (IP and Intf Index) should return false",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteAdded,
				Destination: netip.PrefixFrom(netip.IPv6Unspecified(), 0),
				NextHop: systemops.Nexthop{
					IP: netip.MustParseAddr("2001:db8::1"),
					Intf: &net.Interface{
						Index: 1, Name: "eth0",
					},
				},
			},
			nexthopv4: systemops.Nexthop{
				IP: netip.MustParseAddr("192.168.1.1"),
			},
			nexthopv6: systemops.Nexthop{
				IP: netip.MustParseAddr("2001:db8::1"),
				Intf: &net.Interface{
					Index: 1, Name: "eth0",
				},
			},
			expected: false,
		},
		{
			name: "deleted route matching tracked v4 nexthop (IP and Intf Index) should return true",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteDeleted,
				Destination: netip.PrefixFrom(netip.IPv4Unspecified(), 0),
				NextHop: systemops.Nexthop{
					IP: netip.MustParseAddr("192.168.1.1"),
					Intf: &net.Interface{
						Index: 1, Name: "eth0",
					},
				},
			},
			nexthopv4: systemops.Nexthop{
				IP: netip.MustParseAddr("192.168.1.1"),
				Intf: &net.Interface{
					Index: 1, Name: "eth0",
				},
			},
			nexthopv6: systemops.Nexthop{
				IP: netip.MustParseAddr("2001:db8::1"),
			},
			expected: true,
		},
		{
			name: "deleted route not matching tracked v4 nexthop (different IP) should return false",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteDeleted,
				Destination: netip.PrefixFrom(netip.IPv4Unspecified(), 0),
				NextHop: systemops.Nexthop{
					IP: netip.MustParseAddr("192.168.1.3"), // Different IP
					Intf: &net.Interface{
						Index: 1, Name: "eth0",
					},
				},
			},
			nexthopv4: systemops.Nexthop{
				IP: netip.MustParseAddr("192.168.1.1"),
				Intf: &net.Interface{
					Index: 1, Name: "eth0",
				},
			},
			nexthopv6: systemops.Nexthop{
				IP: netip.MustParseAddr("2001:db8::1"),
			},
			expected: false,
		},
		{
			name: "modified v4 route with same IP, different Intf Index should return true",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteModified,
				Destination: netip.PrefixFrom(netip.IPv4Unspecified(), 0),
				NextHop: systemops.Nexthop{
					IP:   netip.MustParseAddr("192.168.1.1"),
					Intf: &net.Interface{Index: 2, Name: "eth1"}, // Different Intf Index
				},
			},
			nexthopv4: systemops.Nexthop{
				IP:   netip.MustParseAddr("192.168.1.1"),
				Intf: &net.Interface{Index: 1, Name: "eth0"},
			},
			expected: true,
		},
		{
			name: "modified v4 route with same IP, one Intf nil, other non-nil should return true",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteModified,
				Destination: netip.PrefixFrom(netip.IPv4Unspecified(), 0),
				NextHop: systemops.Nexthop{
					IP:   netip.MustParseAddr("192.168.1.1"),
					Intf: nil, // Intf is nil
				},
			},
			nexthopv4: systemops.Nexthop{
				IP:   netip.MustParseAddr("192.168.1.1"),
				Intf: &net.Interface{Index: 1, Name: "eth0"}, // Tracked Intf is not nil
			},
			expected: true,
		},
		{
			name: "added v4 route with same IP, different Intf Index should return true",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteAdded,
				Destination: netip.PrefixFrom(netip.IPv4Unspecified(), 0),
				NextHop: systemops.Nexthop{
					IP:   netip.MustParseAddr("192.168.1.1"),
					Intf: &net.Interface{Index: 2, Name: "eth1"}, // Different Intf Index
				},
			},
			nexthopv4: systemops.Nexthop{
				IP:   netip.MustParseAddr("192.168.1.1"),
				Intf: &net.Interface{Index: 1, Name: "eth0"},
			},
			expected: true,
		},
		{
			name: "deleted v4 route with same IP, different Intf Index should return false",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteDeleted,
				Destination: netip.PrefixFrom(netip.IPv4Unspecified(), 0),
				NextHop: systemops.Nexthop{ // This is the route being deleted
					IP:   netip.MustParseAddr("192.168.1.1"),
					Intf: &net.Interface{Index: 1, Name: "eth0"},
				},
			},
			nexthopv4: systemops.Nexthop{ // This is our tracked nexthop
				IP:   netip.MustParseAddr("192.168.1.1"),
				Intf: &net.Interface{Index: 2, Name: "eth1"}, // Different Intf Index
			},
			expected: false, // Because nexthopv4.Equal(route.NextHop) will be false
		},
		{
			name: "modified v6 route with different IP, same Intf Index should return true",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteModified,
				Destination: netip.PrefixFrom(netip.IPv6Unspecified(), 0),
				NextHop: systemops.Nexthop{
					IP:   netip.MustParseAddr("2001:db8::3"), // Different IP
					Intf: &net.Interface{Index: 1, Name: "eth0"},
				},
			},
			nexthopv6: systemops.Nexthop{
				IP:   netip.MustParseAddr("2001:db8::1"),
				Intf: &net.Interface{Index: 1, Name: "eth0"},
			},
			expected: true,
		},
		{
			name: "modified v6 route with same IP, different Intf Index should return true",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteModified,
				Destination: netip.PrefixFrom(netip.IPv6Unspecified(), 0),
				NextHop: systemops.Nexthop{
					IP:   netip.MustParseAddr("2001:db8::1"),
					Intf: &net.Interface{Index: 2, Name: "eth1"}, // Different Intf Index
				},
			},
			nexthopv6: systemops.Nexthop{
				IP:   netip.MustParseAddr("2001:db8::1"),
				Intf: &net.Interface{Index: 1, Name: "eth0"},
			},
			expected: true,
		},
		{
			name: "modified v6 route with same IP, same Intf Index should return false",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteModified,
				Destination: netip.PrefixFrom(netip.IPv6Unspecified(), 0),
				NextHop: systemops.Nexthop{
					IP:   netip.MustParseAddr("2001:db8::1"),
					Intf: &net.Interface{Index: 1, Name: "eth0"},
				},
			},
			nexthopv6: systemops.Nexthop{
				IP:   netip.MustParseAddr("2001:db8::1"),
				Intf: &net.Interface{Index: 1, Name: "eth0"},
			},
			expected: false,
		},
		{
			name: "deleted v6 route matching tracked nexthop (IP and Intf Index) should return true",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteDeleted,
				Destination: netip.PrefixFrom(netip.IPv6Unspecified(), 0),
				NextHop: systemops.Nexthop{
					IP:   netip.MustParseAddr("2001:db8::1"),
					Intf: &net.Interface{Index: 1, Name: "eth0"},
				},
			},
			nexthopv6: systemops.Nexthop{
				IP:   netip.MustParseAddr("2001:db8::1"),
				Intf: &net.Interface{Index: 1, Name: "eth0"},
			},
			expected: true,
		},
		{
			name: "deleted v6 route not matching tracked nexthop (different IP) should return false",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteDeleted,
				Destination: netip.PrefixFrom(netip.IPv6Unspecified(), 0),
				NextHop: systemops.Nexthop{
					IP:   netip.MustParseAddr("2001:db8::3"), // Different IP
					Intf: &net.Interface{Index: 1, Name: "eth0"},
				},
			},
			nexthopv6: systemops.Nexthop{
				IP:   netip.MustParseAddr("2001:db8::1"),
				Intf: &net.Interface{Index: 1, Name: "eth0"},
			},
			expected: false,
		},
		{
			name: "deleted v6 route not matching tracked nexthop (same IP, different Intf Index) should return false",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteDeleted,
				Destination: netip.PrefixFrom(netip.IPv6Unspecified(), 0),
				NextHop: systemops.Nexthop{ // This is the route being deleted
					IP:   netip.MustParseAddr("2001:db8::1"),
					Intf: &net.Interface{Index: 1, Name: "eth0"},
				},
			},
			nexthopv6: systemops.Nexthop{ // This is our tracked nexthop
				IP:   netip.MustParseAddr("2001:db8::1"),
				Intf: &net.Interface{Index: 2, Name: "eth1"}, // Different Intf Index
			},
			expected: false,
		},
		{
			name: "unknown route type should return false",
			route: systemops.RouteUpdate{
				Type:        systemops.RouteUpdateType(99), // Unknown type
				Destination: netip.PrefixFrom(netip.IPv4Unspecified(), 0),
				NextHop: systemops.Nexthop{
					IP:   netip.MustParseAddr("192.168.1.1"),
					Intf: &net.Interface{Index: 1, Name: "eth0"},
				},
			},
			nexthopv4: systemops.Nexthop{
				IP:   netip.MustParseAddr("192.168.1.2"), // Different from route.NextHop
				Intf: &net.Interface{Index: 1, Name: "eth0"},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := routeChanged(tt.route, tt.nexthopv4, tt.nexthopv6, nil)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsSoftInterface(t *testing.T) {
	tests := []struct {
		name     string
		ifname   string
		expected bool
	}{
		{
			name:     "ISATAP interface should be detected",
			ifname:   "ISATAP tunnel adapter",
			expected: true,
		},
		{
			name:     "lowercase soft interface should be detected",
			ifname:   "isatap.{14A5CF17-CA72-43EC-B4EA-B4B093641B7D}",
			expected: true,
		},
		{
			name:     "Teredo interface should be detected",
			ifname:   "Teredo Tunneling Pseudo-Interface",
			expected: true,
		},
		{
			name:     "GlobalProtect interface should be detected",
			ifname:   "PANGP Virtual Ethernet Adapter",
			expected: true,
		},
		{
			name:     "regular interface should not be detected as soft",
			ifname:   "eth0",
			expected: false,
		},
		{
			name:     "another regular interface should not be detected as soft",
			ifname:   "wlan0",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSoftInterface(tt.ifname)
			assert.Equal(t, tt.expected, result)
		})
	}
}
