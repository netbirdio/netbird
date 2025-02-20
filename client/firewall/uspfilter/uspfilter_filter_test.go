package uspfilter

import (
	"net"
	"net/netip"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	wgdevice "golang.zx2c4.com/wireguard/device"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/mocks"
)

func TestPeerACLFiltering(t *testing.T) {
	localIP := net.ParseIP("100.10.0.100")
	wgNet := &net.IPNet{
		IP:   net.ParseIP("100.10.0.0"),
		Mask: net.CIDRMask(16, 32),
	}

	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
		AddressFunc: func() iface.WGAddress {
			return iface.WGAddress{
				IP:      localIP,
				Network: wgNet,
			}
		},
	}

	manager, err := Create(ifaceMock, false)
	require.NoError(t, err)
	require.NotNil(t, manager)

	t.Cleanup(func() {
		require.NoError(t, manager.Reset(nil))
	})

	manager.wgNetwork = wgNet

	err = manager.UpdateLocalIPs()
	require.NoError(t, err)

	testCases := []struct {
		name            string
		srcIP           string
		dstIP           string
		proto           fw.Protocol
		srcPort         uint16
		dstPort         uint16
		ruleIP          string
		ruleProto       fw.Protocol
		ruleSrcPort     *fw.Port
		ruleDstPort     *fw.Port
		ruleAction      fw.Action
		shouldBeBlocked bool
	}{
		{
			name:            "Allow TCP traffic from WG peer",
			srcIP:           "100.10.0.1",
			dstIP:           "100.10.0.100",
			proto:           fw.ProtocolTCP,
			srcPort:         12345,
			dstPort:         443,
			ruleIP:          "100.10.0.1",
			ruleProto:       fw.ProtocolTCP,
			ruleDstPort:     &fw.Port{Values: []uint16{443}},
			ruleAction:      fw.ActionAccept,
			shouldBeBlocked: false,
		},
		{
			name:            "Allow UDP traffic from WG peer",
			srcIP:           "100.10.0.1",
			dstIP:           "100.10.0.100",
			proto:           fw.ProtocolUDP,
			srcPort:         12345,
			dstPort:         53,
			ruleIP:          "100.10.0.1",
			ruleProto:       fw.ProtocolUDP,
			ruleDstPort:     &fw.Port{Values: []uint16{53}},
			ruleAction:      fw.ActionAccept,
			shouldBeBlocked: false,
		},
		{
			name:            "Allow ICMP traffic from WG peer",
			srcIP:           "100.10.0.1",
			dstIP:           "100.10.0.100",
			proto:           fw.ProtocolICMP,
			ruleIP:          "100.10.0.1",
			ruleProto:       fw.ProtocolICMP,
			ruleAction:      fw.ActionAccept,
			shouldBeBlocked: false,
		},
		{
			name:            "Allow all traffic from WG peer",
			srcIP:           "100.10.0.1",
			dstIP:           "100.10.0.100",
			proto:           fw.ProtocolTCP,
			srcPort:         12345,
			dstPort:         443,
			ruleIP:          "100.10.0.1",
			ruleProto:       fw.ProtocolALL,
			ruleAction:      fw.ActionAccept,
			shouldBeBlocked: false,
		},
		{
			name:            "Allow traffic from non-WG source",
			srcIP:           "192.168.1.1",
			dstIP:           "100.10.0.100",
			proto:           fw.ProtocolTCP,
			srcPort:         12345,
			dstPort:         443,
			ruleIP:          "192.168.1.1",
			ruleProto:       fw.ProtocolTCP,
			ruleDstPort:     &fw.Port{Values: []uint16{443}},
			ruleAction:      fw.ActionAccept,
			shouldBeBlocked: false,
		},
		{
			name:            "Allow all traffic with 0.0.0.0 rule",
			srcIP:           "100.10.0.1",
			dstIP:           "100.10.0.100",
			proto:           fw.ProtocolTCP,
			srcPort:         12345,
			dstPort:         443,
			ruleIP:          "0.0.0.0",
			ruleProto:       fw.ProtocolALL,
			ruleAction:      fw.ActionAccept,
			shouldBeBlocked: false,
		},
		{
			name:            "Allow TCP traffic within port range",
			srcIP:           "100.10.0.1",
			dstIP:           "100.10.0.100",
			proto:           fw.ProtocolTCP,
			srcPort:         12345,
			dstPort:         8080,
			ruleIP:          "100.10.0.1",
			ruleProto:       fw.ProtocolTCP,
			ruleDstPort:     &fw.Port{IsRange: true, Values: []uint16{8000, 8100}},
			ruleAction:      fw.ActionAccept,
			shouldBeBlocked: false,
		},
		{
			name:            "Block TCP traffic outside port range",
			srcIP:           "100.10.0.1",
			dstIP:           "100.10.0.100",
			proto:           fw.ProtocolTCP,
			srcPort:         12345,
			dstPort:         7999,
			ruleIP:          "100.10.0.1",
			ruleProto:       fw.ProtocolTCP,
			ruleDstPort:     &fw.Port{IsRange: true, Values: []uint16{8000, 8100}},
			ruleAction:      fw.ActionAccept,
			shouldBeBlocked: true,
		},
		{
			name:            "Allow TCP traffic with source port range",
			srcIP:           "100.10.0.1",
			dstIP:           "100.10.0.100",
			proto:           fw.ProtocolTCP,
			srcPort:         32100,
			dstPort:         443,
			ruleIP:          "100.10.0.1",
			ruleProto:       fw.ProtocolTCP,
			ruleSrcPort:     &fw.Port{IsRange: true, Values: []uint16{32000, 33000}},
			ruleDstPort:     &fw.Port{Values: []uint16{443}},
			ruleAction:      fw.ActionAccept,
			shouldBeBlocked: false,
		},
		{
			name:            "Block TCP traffic outside source port range",
			srcIP:           "100.10.0.1",
			dstIP:           "100.10.0.100",
			proto:           fw.ProtocolTCP,
			srcPort:         31999,
			dstPort:         443,
			ruleIP:          "100.10.0.1",
			ruleProto:       fw.ProtocolTCP,
			ruleSrcPort:     &fw.Port{IsRange: true, Values: []uint16{32000, 33000}},
			ruleDstPort:     &fw.Port{Values: []uint16{443}},
			ruleAction:      fw.ActionAccept,
			shouldBeBlocked: true,
		},
	}

	t.Run("Implicit DROP (no rules)", func(t *testing.T) {
		packet := createTestPacket(t, "100.10.0.1", "100.10.0.100", fw.ProtocolTCP, 12345, 443)
		isDropped := manager.DropIncoming(packet)
		require.True(t, isDropped, "Packet should be dropped when no rules exist")
	})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rules, err := manager.AddPeerFiltering(
				net.ParseIP(tc.ruleIP),
				tc.ruleProto,
				tc.ruleSrcPort,
				tc.ruleDstPort,
				tc.ruleAction,
				"",
				tc.name,
			)
			require.NoError(t, err)
			require.NotEmpty(t, rules)

			t.Cleanup(func() {
				for _, rule := range rules {
					require.NoError(t, manager.DeletePeerRule(rule))
				}
			})

			packet := createTestPacket(t, tc.srcIP, tc.dstIP, tc.proto, tc.srcPort, tc.dstPort)
			isDropped := manager.DropIncoming(packet)
			require.Equal(t, tc.shouldBeBlocked, isDropped)
		})
	}
}

func createTestPacket(t *testing.T, srcIP, dstIP string, proto fw.Protocol, srcPort, dstPort uint16) []byte {
	t.Helper()

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	ipLayer := &layers.IPv4{
		Version: 4,
		TTL:     64,
		SrcIP:   net.ParseIP(srcIP),
		DstIP:   net.ParseIP(dstIP),
	}

	var err error
	switch proto {
	case fw.ProtocolTCP:
		ipLayer.Protocol = layers.IPProtocolTCP
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
		}
		err = tcp.SetNetworkLayerForChecksum(ipLayer)
		require.NoError(t, err)
		err = gopacket.SerializeLayers(buf, opts, ipLayer, tcp)

	case fw.ProtocolUDP:
		ipLayer.Protocol = layers.IPProtocolUDP
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		err = udp.SetNetworkLayerForChecksum(ipLayer)
		require.NoError(t, err)
		err = gopacket.SerializeLayers(buf, opts, ipLayer, udp)

	case fw.ProtocolICMP:
		ipLayer.Protocol = layers.IPProtocolICMPv4
		icmp := &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		}
		err = gopacket.SerializeLayers(buf, opts, ipLayer, icmp)

	default:
		err = gopacket.SerializeLayers(buf, opts, ipLayer)
	}

	require.NoError(t, err)
	return buf.Bytes()
}

func setupRoutedManager(tb testing.TB, network string) *Manager {
	tb.Helper()

	ctrl := gomock.NewController(tb)
	dev := mocks.NewMockDevice(ctrl)
	dev.EXPECT().MTU().Return(1500, nil).AnyTimes()

	localIP, wgNet, err := net.ParseCIDR(network)
	require.NoError(tb, err)

	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
		AddressFunc: func() iface.WGAddress {
			return iface.WGAddress{
				IP:      localIP,
				Network: wgNet,
			}
		},
		GetDeviceFunc: func() *device.FilteredDevice {
			return &device.FilteredDevice{Device: dev}
		},
		GetWGDeviceFunc: func() *wgdevice.Device {
			return &wgdevice.Device{}
		},
	}

	manager, err := Create(ifaceMock, false)
	require.NoError(tb, manager.EnableRouting())
	require.NoError(tb, err)
	require.NotNil(tb, manager)
	require.True(tb, manager.routingEnabled)
	require.False(tb, manager.nativeRouter)

	tb.Cleanup(func() {
		require.NoError(tb, manager.Reset(nil))
	})

	return manager
}

func TestRouteACLFiltering(t *testing.T) {
	manager := setupRoutedManager(t, "10.10.0.100/16")

	type rule struct {
		sources []netip.Prefix
		dest    netip.Prefix
		proto   fw.Protocol
		srcPort *fw.Port
		dstPort *fw.Port
		action  fw.Action
	}

	testCases := []struct {
		name       string
		srcIP      string
		dstIP      string
		proto      fw.Protocol
		srcPort    uint16
		dstPort    uint16
		rule       rule
		shouldPass bool
	}{
		{
			name:    "Allow TCP with specific source and destination",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 443,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolTCP,
				dstPort: &fw.Port{Values: []uint16{443}},
				action:  fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:    "Allow any source to specific destination",
			srcIP:   "172.16.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 443,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolTCP,
				dstPort: &fw.Port{Values: []uint16{443}},
				action:  fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:    "Allow any source to any destination",
			srcIP:   "172.16.0.1",
			dstIP:   "203.0.113.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 443,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
				dest:    netip.MustParsePrefix("0.0.0.0/0"),
				proto:   fw.ProtocolTCP,
				dstPort: &fw.Port{Values: []uint16{443}},
				action:  fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:    "Allow UDP DNS traffic",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.53",
			proto:   fw.ProtocolUDP,
			srcPort: 54321,
			dstPort: 53,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolUDP,
				dstPort: &fw.Port{Values: []uint16{53}},
				action:  fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:  "Allow ICMP to any destination",
			srcIP: "100.10.0.1",
			dstIP: "8.8.8.8",
			proto: fw.ProtocolICMP,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("0.0.0.0/0"),
				proto:   fw.ProtocolICMP,
				action:  fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:    "Allow all protocols but specific port",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 80,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolALL,
				dstPort: &fw.Port{Values: []uint16{80}},
				action:  fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:    "Implicit deny - wrong destination port",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 8080,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolTCP,
				dstPort: &fw.Port{Values: []uint16{80}},
				action:  fw.ActionAccept,
			},
			shouldPass: false,
		},
		{
			name:    "Implicit deny - wrong protocol",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolUDP,
			srcPort: 12345,
			dstPort: 80,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolTCP,
				dstPort: &fw.Port{Values: []uint16{80}},
				action:  fw.ActionAccept,
			},
			shouldPass: false,
		},
		{
			name:    "Implicit deny - wrong source network",
			srcIP:   "172.16.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 80,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolTCP,
				dstPort: &fw.Port{Values: []uint16{80}},
				action:  fw.ActionAccept,
			},
			shouldPass: false,
		},
		{
			name:    "Source port match",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 80,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolTCP,
				srcPort: &fw.Port{Values: []uint16{12345}},
				action:  fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:    "Multiple source networks",
			srcIP:   "172.16.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 80,
			rule: rule{
				sources: []netip.Prefix{
					netip.MustParsePrefix("100.10.0.0/16"),
					netip.MustParsePrefix("172.16.0.0/16"),
				},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolTCP,
				dstPort: &fw.Port{Values: []uint16{80}},
				action:  fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:  "Allow ALL protocol without ports",
			srcIP: "100.10.0.1",
			dstIP: "192.168.1.100",
			proto: fw.ProtocolICMP,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolALL,
				action:  fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:    "Allow ALL protocol with specific ports",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 80,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolALL,
				dstPort: &fw.Port{Values: []uint16{80}},
				action:  fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:  "Multiple source networks with mismatched protocol",
			srcIP: "172.16.0.1",
			dstIP: "192.168.1.100",
			// Should not match TCP rule
			proto:   fw.ProtocolUDP,
			srcPort: 12345,
			dstPort: 80,
			rule: rule{
				sources: []netip.Prefix{
					netip.MustParsePrefix("100.10.0.0/16"),
					netip.MustParsePrefix("172.16.0.0/16"),
				},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolTCP,
				dstPort: &fw.Port{Values: []uint16{80}},
				action:  fw.ActionAccept,
			},
			shouldPass: false,
		},
		{
			name:    "Allow multiple destination ports",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 8080,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolTCP,
				dstPort: &fw.Port{Values: []uint16{80, 8080, 443}},
				action:  fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:    "Allow multiple source ports",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 80,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolTCP,
				srcPort: &fw.Port{Values: []uint16{12345, 12346, 12347}},
				action:  fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:    "Allow ALL protocol with both src and dst ports",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 80,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolALL,
				srcPort: &fw.Port{Values: []uint16{12345}},
				dstPort: &fw.Port{Values: []uint16{80}},
				action:  fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:    "Port Range - Within Range",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 8080,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolTCP,
				dstPort: &fw.Port{
					IsRange: true,
					Values:  []uint16{8000, 8100},
				},
				action: fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:    "Port Range - Outside Range",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 7999,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolTCP,
				dstPort: &fw.Port{
					IsRange: true,
					Values:  []uint16{8000, 8100},
				},
				action: fw.ActionAccept,
			},
			shouldPass: false,
		},
		{
			name:    "Source Port Range - Within Range",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 32100,
			dstPort: 80,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolTCP,
				srcPort: &fw.Port{
					IsRange: true,
					Values:  []uint16{32000, 33000},
				},
				action: fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:    "Mixed Port Specification - Range and Single",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 32100,
			dstPort: 443,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolTCP,
				srcPort: &fw.Port{
					IsRange: true,
					Values:  []uint16{32000, 33000},
				},
				dstPort: &fw.Port{
					Values: []uint16{443},
				},
				action: fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:    "Edge Case - Port at Range Boundary",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 8100,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolTCP,
				dstPort: &fw.Port{
					IsRange: true,
					Values:  []uint16{8000, 8100},
				},
				action: fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:    "UDP Port Range",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolUDP,
			srcPort: 12345,
			dstPort: 5060,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolUDP,
				dstPort: &fw.Port{
					IsRange: true,
					Values:  []uint16{5060, 5070},
				},
				action: fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:    "ALL Protocol with Port Range",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 8080,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolALL,
				dstPort: &fw.Port{
					IsRange: true,
					Values:  []uint16{8000, 8100},
				},
				action: fw.ActionAccept,
			},
			shouldPass: true,
		},
		{
			name:    "Drop TCP traffic to specific destination",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 443,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolTCP,
				dstPort: &fw.Port{Values: []uint16{443}},
				action:  fw.ActionDrop,
			},
			shouldPass: false,
		},
		{
			name:    "Drop all traffic to specific destination",
			srcIP:   "100.10.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 80,
			rule: rule{
				sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolALL,
				action:  fw.ActionDrop,
			},
			shouldPass: false,
		},
		{
			name:    "Drop traffic from multiple source networks",
			srcIP:   "172.16.0.1",
			dstIP:   "192.168.1.100",
			proto:   fw.ProtocolTCP,
			srcPort: 12345,
			dstPort: 80,
			rule: rule{
				sources: []netip.Prefix{
					netip.MustParsePrefix("100.10.0.0/16"),
					netip.MustParsePrefix("172.16.0.0/16"),
				},
				dest:    netip.MustParsePrefix("192.168.1.0/24"),
				proto:   fw.ProtocolTCP,
				dstPort: &fw.Port{Values: []uint16{80}},
				action:  fw.ActionDrop,
			},
			shouldPass: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rule, err := manager.AddRouteFiltering(
				tc.rule.sources,
				tc.rule.dest,
				tc.rule.proto,
				tc.rule.srcPort,
				tc.rule.dstPort,
				tc.rule.action,
			)
			require.NoError(t, err)
			require.NotNil(t, rule)

			t.Cleanup(func() {
				require.NoError(t, manager.DeleteRouteRule(rule))
			})

			srcIP := net.ParseIP(tc.srcIP)
			dstIP := net.ParseIP(tc.dstIP)

			// testing routeACLsPass only and not DropIncoming, as routed packets are dropped after being passed
			// to the forwarder
			isAllowed := manager.routeACLsPass(srcIP, dstIP, tc.proto, tc.srcPort, tc.dstPort)
			require.Equal(t, tc.shouldPass, isAllowed)
		})
	}
}

func TestRouteACLOrder(t *testing.T) {
	manager := setupRoutedManager(t, "10.10.0.100/16")

	type testCase struct {
		name  string
		rules []struct {
			sources []netip.Prefix
			dest    netip.Prefix
			proto   fw.Protocol
			srcPort *fw.Port
			dstPort *fw.Port
			action  fw.Action
		}
		packets []struct {
			srcIP      string
			dstIP      string
			proto      fw.Protocol
			srcPort    uint16
			dstPort    uint16
			shouldPass bool
		}
	}

	testCases := []testCase{
		{
			name: "Drop rules take precedence over accept",
			rules: []struct {
				sources []netip.Prefix
				dest    netip.Prefix
				proto   fw.Protocol
				srcPort *fw.Port
				dstPort *fw.Port
				action  fw.Action
			}{
				{
					// Accept rule added first
					sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
					dest:    netip.MustParsePrefix("192.168.1.0/24"),
					proto:   fw.ProtocolTCP,
					dstPort: &fw.Port{Values: []uint16{80, 443}},
					action:  fw.ActionAccept,
				},
				{
					// Drop rule added second but should be evaluated first
					sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
					dest:    netip.MustParsePrefix("192.168.1.0/24"),
					proto:   fw.ProtocolTCP,
					dstPort: &fw.Port{Values: []uint16{443}},
					action:  fw.ActionDrop,
				},
			},
			packets: []struct {
				srcIP      string
				dstIP      string
				proto      fw.Protocol
				srcPort    uint16
				dstPort    uint16
				shouldPass bool
			}{
				{
					// Should be dropped by the drop rule
					srcIP:      "100.10.0.1",
					dstIP:      "192.168.1.100",
					proto:      fw.ProtocolTCP,
					srcPort:    12345,
					dstPort:    443,
					shouldPass: false,
				},
				{
					// Should be allowed by the accept rule (port 80 not in drop rule)
					srcIP:      "100.10.0.1",
					dstIP:      "192.168.1.100",
					proto:      fw.ProtocolTCP,
					srcPort:    12345,
					dstPort:    80,
					shouldPass: true,
				},
			},
		},
		{
			name: "Multiple drop rules take precedence",
			rules: []struct {
				sources []netip.Prefix
				dest    netip.Prefix
				proto   fw.Protocol
				srcPort *fw.Port
				dstPort *fw.Port
				action  fw.Action
			}{
				{
					// Accept all
					sources: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
					dest:    netip.MustParsePrefix("0.0.0.0/0"),
					proto:   fw.ProtocolALL,
					action:  fw.ActionAccept,
				},
				{
					// Drop specific port
					sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
					dest:    netip.MustParsePrefix("192.168.1.0/24"),
					proto:   fw.ProtocolTCP,
					dstPort: &fw.Port{Values: []uint16{443}},
					action:  fw.ActionDrop,
				},
				{
					// Drop different port
					sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
					dest:    netip.MustParsePrefix("192.168.1.0/24"),
					proto:   fw.ProtocolTCP,
					dstPort: &fw.Port{Values: []uint16{80}},
					action:  fw.ActionDrop,
				},
			},
			packets: []struct {
				srcIP      string
				dstIP      string
				proto      fw.Protocol
				srcPort    uint16
				dstPort    uint16
				shouldPass bool
			}{
				{
					// Should be dropped by first drop rule
					srcIP:      "100.10.0.1",
					dstIP:      "192.168.1.100",
					proto:      fw.ProtocolTCP,
					srcPort:    12345,
					dstPort:    443,
					shouldPass: false,
				},
				{
					// Should be dropped by second drop rule
					srcIP:      "100.10.0.1",
					dstIP:      "192.168.1.100",
					proto:      fw.ProtocolTCP,
					srcPort:    12345,
					dstPort:    80,
					shouldPass: false,
				},
				{
					// Should be allowed by the accept rule (different port)
					srcIP:      "100.10.0.1",
					dstIP:      "192.168.1.100",
					proto:      fw.ProtocolTCP,
					srcPort:    12345,
					dstPort:    8080,
					shouldPass: true,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var rules []fw.Rule
			for _, r := range tc.rules {
				rule, err := manager.AddRouteFiltering(
					r.sources,
					r.dest,
					r.proto,
					r.srcPort,
					r.dstPort,
					r.action,
				)
				require.NoError(t, err)
				require.NotNil(t, rule)
				rules = append(rules, rule)
			}

			t.Cleanup(func() {
				for _, rule := range rules {
					require.NoError(t, manager.DeleteRouteRule(rule))
				}
			})

			for i, p := range tc.packets {
				srcIP := net.ParseIP(p.srcIP)
				dstIP := net.ParseIP(p.dstIP)

				isAllowed := manager.routeACLsPass(srcIP, dstIP, p.proto, p.srcPort, p.dstPort)
				require.Equal(t, p.shouldPass, isAllowed, "packet %d failed", i)
			}
		})
	}
}
