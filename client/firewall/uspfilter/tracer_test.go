package uspfilter

import (
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/forwarder"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

func verifyTraceStages(t *testing.T, trace *PacketTrace, expectedStages []PacketStage) {
	t.Logf("Trace results: %v", trace.Results)
	actualStages := make([]PacketStage, 0, len(trace.Results))
	for _, result := range trace.Results {
		actualStages = append(actualStages, result.Stage)
		t.Logf("Stage: %s, Message: %s, Allowed: %v", result.Stage, result.Message, result.Allowed)
	}

	require.ElementsMatch(t, expectedStages, actualStages, "Trace stages don't match expected stages")
}

func verifyFinalDisposition(t *testing.T, trace *PacketTrace, expectedAllowed bool) {
	require.NotEmpty(t, trace.Results, "Trace should have results")
	lastResult := trace.Results[len(trace.Results)-1]
	require.Equal(t, StageCompleted, lastResult.Stage, "Last stage should be 'Completed'")
	require.Equal(t, expectedAllowed, lastResult.Allowed, "Final disposition incorrect")
}

func TestTracePacket(t *testing.T) {
	setupTracerTest := func(statefulMode bool) *Manager {
		ifaceMock := &IFaceMock{
			SetFilterFunc: func(device.PacketFilter) error { return nil },
			AddressFunc: func() wgaddr.Address {
				return wgaddr.Address{
					IP:      netip.MustParseAddr("100.10.0.100"),
					Network: netip.MustParsePrefix("100.10.0.0/16"),
				}
			},
		}

		m, err := Create(ifaceMock, false, flowLogger, iface.DefaultMTU)
		require.NoError(t, err)

		if !statefulMode {
			m.stateful = false
		}

		return m
	}

	createPacketBuilder := func(srcIP, dstIP string, protocol fw.Protocol, srcPort, dstPort uint16, direction fw.RuleDirection) *PacketBuilder {
		builder := &PacketBuilder{
			SrcIP:     netip.MustParseAddr(srcIP),
			DstIP:     netip.MustParseAddr(dstIP),
			Protocol:  protocol,
			SrcPort:   srcPort,
			DstPort:   dstPort,
			Direction: direction,
		}

		if protocol == "tcp" {
			builder.TCPState = &TCPState{SYN: true}
		}

		return builder
	}

	createICMPPacketBuilder := func(srcIP, dstIP string, icmpType, icmpCode uint8, direction fw.RuleDirection) *PacketBuilder {
		return &PacketBuilder{
			SrcIP:     netip.MustParseAddr(srcIP),
			DstIP:     netip.MustParseAddr(dstIP),
			Protocol:  "icmp",
			ICMPType:  icmpType,
			ICMPCode:  icmpCode,
			Direction: direction,
		}
	}

	testCases := []struct {
		name           string
		setup          func(*Manager)
		packetBuilder  func() *PacketBuilder
		expectedStages []PacketStage
		expectedAllow  bool
	}{
		{
			name: "LocalTraffic_ACLAllowed",
			setup: func(m *Manager) {
				ip := net.ParseIP("1.1.1.1")
				proto := fw.ProtocolTCP
				port := &fw.Port{Values: []uint16{80}}
				action := fw.ActionAccept
				_, err := m.AddPeerFiltering(nil, ip, proto, nil, port, action, "")
				require.NoError(t, err)
			},
			packetBuilder: func() *PacketBuilder {
				return createPacketBuilder("1.1.1.1", "100.10.0.100", "tcp", 12345, 80, fw.RuleDirectionIN)
			},
			expectedStages: []PacketStage{
				StageReceived,
				StageInboundPortDNAT,
				StageInbound1to1NAT,
				StageConntrack,
				StageRouting,
				StagePeerACL,
				StageCompleted,
			},
			expectedAllow: true,
		},
		{
			name: "LocalTraffic_ACLDenied",
			setup: func(m *Manager) {
				ip := net.ParseIP("1.1.1.1")
				proto := fw.ProtocolTCP
				port := &fw.Port{Values: []uint16{80}}
				action := fw.ActionDrop
				_, err := m.AddPeerFiltering(nil, ip, proto, nil, port, action, "")
				require.NoError(t, err)
			},
			packetBuilder: func() *PacketBuilder {
				return createPacketBuilder("1.1.1.1", "100.10.0.100", "tcp", 12345, 80, fw.RuleDirectionIN)
			},
			expectedStages: []PacketStage{
				StageReceived,
				StageInboundPortDNAT,
				StageInbound1to1NAT,
				StageConntrack,
				StageRouting,
				StagePeerACL,
				StageCompleted,
			},
			expectedAllow: false,
		},
		{
			name: "LocalTraffic_WithForwarder",
			setup: func(m *Manager) {
				m.netstack = true
				m.localForwarding = true

				m.forwarder.Store(&forwarder.Forwarder{})

				ip := net.ParseIP("1.1.1.1")
				proto := fw.ProtocolTCP
				port := &fw.Port{Values: []uint16{80}}
				action := fw.ActionAccept
				_, err := m.AddPeerFiltering(nil, ip, proto, nil, port, action, "")
				require.NoError(t, err)
			},
			packetBuilder: func() *PacketBuilder {
				return createPacketBuilder("1.1.1.1", "100.10.0.100", "tcp", 12345, 80, fw.RuleDirectionIN)
			},
			expectedStages: []PacketStage{
				StageReceived,
				StageInboundPortDNAT,
				StageInbound1to1NAT,
				StageConntrack,
				StageRouting,
				StagePeerACL,
				StageForwarding,
				StageCompleted,
			},
			expectedAllow: true,
		},
		{
			name: "LocalTraffic_WithoutForwarder",
			setup: func(m *Manager) {
				m.netstack = true
				m.localForwarding = false

				ip := net.ParseIP("1.1.1.1")
				proto := fw.ProtocolTCP
				port := &fw.Port{Values: []uint16{80}}
				action := fw.ActionAccept
				_, err := m.AddPeerFiltering(nil, ip, proto, nil, port, action, "")
				require.NoError(t, err)
			},
			packetBuilder: func() *PacketBuilder {
				return createPacketBuilder("1.1.1.1", "100.10.0.100", "tcp", 12345, 80, fw.RuleDirectionIN)
			},
			expectedStages: []PacketStage{
				StageReceived,
				StageInboundPortDNAT,
				StageInbound1to1NAT,
				StageConntrack,
				StageRouting,
				StagePeerACL,
				StageCompleted,
			},
			expectedAllow: true,
		},
		{
			name: "RoutedTraffic_ACLAllowed",
			setup: func(m *Manager) {
				m.routingEnabled.Store(true)
				m.nativeRouter.Store(false)

				m.forwarder.Store(&forwarder.Forwarder{})

				src := netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 32)
				dst := netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 17, 2}), 32)
				_, err := m.AddRouteFiltering(nil, []netip.Prefix{src}, fw.Network{Prefix: dst}, fw.ProtocolTCP, nil, &fw.Port{Values: []uint16{80}}, fw.ActionAccept)
				require.NoError(t, err)
			},
			packetBuilder: func() *PacketBuilder {
				return createPacketBuilder("1.1.1.1", "192.168.17.2", "tcp", 12345, 80, fw.RuleDirectionIN)
			},
			expectedStages: []PacketStage{
				StageReceived,
				StageInboundPortDNAT,
				StageInbound1to1NAT,
				StageConntrack,
				StageRouting,
				StageRouteACL,
				StageForwarding,
				StageCompleted,
			},
			expectedAllow: true,
		},
		{
			name: "RoutedTraffic_ACLDenied",
			setup: func(m *Manager) {
				m.routingEnabled.Store(true)
				m.nativeRouter.Store(false)

				src := netip.PrefixFrom(netip.AddrFrom4([4]byte{1, 1, 1, 1}), 32)
				dst := netip.PrefixFrom(netip.AddrFrom4([4]byte{192, 168, 17, 2}), 32)
				_, err := m.AddRouteFiltering(nil, []netip.Prefix{src}, fw.Network{Prefix: dst}, fw.ProtocolTCP, nil, &fw.Port{Values: []uint16{80}}, fw.ActionDrop)
				require.NoError(t, err)
			},
			packetBuilder: func() *PacketBuilder {
				return createPacketBuilder("1.1.1.1", "192.168.17.2", "tcp", 12345, 80, fw.RuleDirectionIN)
			},
			expectedStages: []PacketStage{
				StageReceived,
				StageInboundPortDNAT,
				StageInbound1to1NAT,
				StageConntrack,
				StageRouting,
				StageRouteACL,
				StageCompleted,
			},
			expectedAllow: false,
		},
		{
			name: "RoutedTraffic_NativeRouter",
			setup: func(m *Manager) {
				m.routingEnabled.Store(true)
				m.nativeRouter.Store(true)
			},
			packetBuilder: func() *PacketBuilder {
				return createPacketBuilder("1.1.1.1", "192.168.17.2", "tcp", 12345, 80, fw.RuleDirectionIN)
			},
			expectedStages: []PacketStage{
				StageReceived,
				StageInboundPortDNAT,
				StageInbound1to1NAT,
				StageConntrack,
				StageRouting,
				StageRouteACL,
				StageForwarding,
				StageCompleted,
			},
			expectedAllow: true,
		},
		{
			name: "RoutedTraffic_RoutingDisabled",
			setup: func(m *Manager) {
				m.routingEnabled.Store(false)
			},
			packetBuilder: func() *PacketBuilder {
				return createPacketBuilder("1.1.1.1", "192.168.17.2", "tcp", 12345, 80, fw.RuleDirectionIN)
			},
			expectedStages: []PacketStage{
				StageReceived,
				StageInboundPortDNAT,
				StageInbound1to1NAT,
				StageConntrack,
				StageRouting,
				StageCompleted,
			},
			expectedAllow: false,
		},
		{
			name: "ConnectionTracking_Hit",
			setup: func(m *Manager) {
				srcIP := netip.MustParseAddr("100.10.0.100")
				dstIP := netip.MustParseAddr("1.1.1.1")
				srcPort := uint16(12345)
				dstPort := uint16(80)

				m.tcpTracker.TrackOutbound(srcIP, dstIP, srcPort, dstPort, conntrack.TCPSyn, 0)
			},
			packetBuilder: func() *PacketBuilder {
				pb := createPacketBuilder("1.1.1.1", "100.10.0.100", "tcp", 80, 12345, fw.RuleDirectionIN)
				pb.TCPState = &TCPState{SYN: true, ACK: true}
				return pb
			},
			expectedStages: []PacketStage{
				StageReceived,
				StageInboundPortDNAT,
				StageInbound1to1NAT,
				StageConntrack,
				StageCompleted,
			},
			expectedAllow: true,
		},
		{
			name: "OutboundTraffic",
			setup: func(m *Manager) {
			},
			packetBuilder: func() *PacketBuilder {
				return createPacketBuilder("100.10.0.100", "1.1.1.1", "tcp", 12345, 80, fw.RuleDirectionOUT)
			},
			expectedStages: []PacketStage{
				StageReceived,
				StageOutbound1to1NAT,
				StageOutboundPortReverse,
				StageCompleted,
			},
			expectedAllow: true,
		},
		{
			name: "ICMPEchoRequest",
			setup: func(m *Manager) {
				ip := net.ParseIP("1.1.1.1")
				proto := fw.ProtocolICMP
				action := fw.ActionAccept
				_, err := m.AddPeerFiltering(nil, ip, proto, nil, nil, action, "")
				require.NoError(t, err)
			},
			packetBuilder: func() *PacketBuilder {
				return createICMPPacketBuilder("1.1.1.1", "100.10.0.100", 8, 0, fw.RuleDirectionIN)
			},
			expectedStages: []PacketStage{
				StageReceived,
				StageInboundPortDNAT,
				StageInbound1to1NAT,
				StageConntrack,
				StageRouting,
				StagePeerACL,
				StageCompleted,
			},
			expectedAllow: true,
		},
		{
			name: "ICMPDestinationUnreachable",
			setup: func(m *Manager) {
				ip := net.ParseIP("1.1.1.1")
				proto := fw.ProtocolICMP
				action := fw.ActionDrop
				_, err := m.AddPeerFiltering(nil, ip, proto, nil, nil, action, "")
				require.NoError(t, err)
			},
			packetBuilder: func() *PacketBuilder {
				return createICMPPacketBuilder("1.1.1.1", "100.10.0.100", 3, 0, fw.RuleDirectionIN)
			},
			expectedStages: []PacketStage{
				StageReceived,
				StageInboundPortDNAT,
				StageInbound1to1NAT,
				StageConntrack,
				StageRouting,
				StagePeerACL,
				StageCompleted,
			},
			expectedAllow: true,
		},
		{
			name: "UDPTraffic_WithoutHook",
			setup: func(m *Manager) {
				ip := net.ParseIP("1.1.1.1")
				proto := fw.ProtocolUDP
				port := &fw.Port{Values: []uint16{53}}
				action := fw.ActionAccept
				_, err := m.AddPeerFiltering(nil, ip, proto, nil, port, action, "")
				require.NoError(t, err)
			},
			packetBuilder: func() *PacketBuilder {
				return createPacketBuilder("1.1.1.1", "100.10.0.100", "udp", 12345, 53, fw.RuleDirectionIN)
			},
			expectedStages: []PacketStage{
				StageReceived,
				StageInboundPortDNAT,
				StageInbound1to1NAT,
				StageConntrack,
				StageRouting,
				StagePeerACL,
				StageCompleted,
			},
			expectedAllow: true,
		},
		{
			name: "UDPTraffic_WithHook",
			setup: func(m *Manager) {
				hookFunc := func([]byte) bool {
					return true
				}
				m.AddUDPPacketHook(true, netip.MustParseAddr("1.1.1.1"), 53, hookFunc)
			},
			packetBuilder: func() *PacketBuilder {
				return createPacketBuilder("1.1.1.1", "100.10.0.100", "udp", 12345, 53, fw.RuleDirectionIN)
			},
			expectedStages: []PacketStage{
				StageReceived,
				StageInboundPortDNAT,
				StageInbound1to1NAT,
				StageConntrack,
				StageRouting,
				StagePeerACL,
				StageCompleted,
			},
			expectedAllow: false,
		},
		{
			name: "StatefulDisabled_NoTracking",
			setup: func(m *Manager) {
				m.stateful = false

				ip := net.ParseIP("1.1.1.1")
				proto := fw.ProtocolTCP
				port := &fw.Port{Values: []uint16{80}}
				action := fw.ActionDrop
				_, err := m.AddPeerFiltering(nil, ip, proto, nil, port, action, "")
				require.NoError(t, err)
			},
			packetBuilder: func() *PacketBuilder {
				return createPacketBuilder("1.1.1.1", "100.10.0.100", "tcp", 12345, 80, fw.RuleDirectionIN)
			},
			expectedStages: []PacketStage{
				StageReceived,
				StageInboundPortDNAT,
				StageInbound1to1NAT,
				StageRouting,
				StagePeerACL,
				StageCompleted,
			},
			expectedAllow: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := setupTracerTest(true)

			tc.setup(m)

			require.True(t, m.localipmanager.IsLocalIP(netip.MustParseAddr("100.10.0.100")),
				"100.10.0.100 should be recognized as a local IP")
			require.False(t, m.localipmanager.IsLocalIP(netip.MustParseAddr("192.168.17.2")),
				"192.168.17.2 should not be recognized as a local IP")

			pb := tc.packetBuilder()

			trace, err := m.TracePacketFromBuilder(pb)
			require.NoError(t, err)

			verifyTraceStages(t, trace, tc.expectedStages)
			verifyFinalDisposition(t, trace, tc.expectedAllow)
		})
	}
}
