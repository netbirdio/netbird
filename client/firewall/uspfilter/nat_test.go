package uspfilter

import (
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
)

// TestDNATTranslationCorrectness verifies DNAT translation works correctly
func TestDNATTranslationCorrectness(t *testing.T) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger, iface.DefaultMTU)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	originalIP := netip.MustParseAddr("192.168.1.100")
	translatedIP := netip.MustParseAddr("10.0.0.100")
	srcIP := netip.MustParseAddr("172.16.0.1")

	// Add DNAT mapping
	err = manager.AddInternalDNATMapping(originalIP, translatedIP)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		protocol layers.IPProtocol
		srcPort  uint16
		dstPort  uint16
	}{
		{"TCP", layers.IPProtocolTCP, 12345, 80},
		{"UDP", layers.IPProtocolUDP, 12345, 53},
		{"ICMP", layers.IPProtocolICMPv4, 0, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test outbound DNAT translation
			outboundPacket := generateDNATTestPacket(t, srcIP, originalIP, tc.protocol, tc.srcPort, tc.dstPort)
			originalOutbound := make([]byte, len(outboundPacket))
			copy(originalOutbound, outboundPacket)

			// Process outbound packet (should translate destination)
			translated := manager.translateOutboundDNAT(outboundPacket, parsePacket(t, outboundPacket))
			require.True(t, translated, "Outbound packet should be translated")

			// Verify destination IP was changed
			dstIPAfter := netip.AddrFrom4([4]byte{outboundPacket[16], outboundPacket[17], outboundPacket[18], outboundPacket[19]})
			require.Equal(t, translatedIP, dstIPAfter, "Destination IP should be translated")

			// Test inbound reverse DNAT translation
			inboundPacket := generateDNATTestPacket(t, translatedIP, srcIP, tc.protocol, tc.dstPort, tc.srcPort)
			originalInbound := make([]byte, len(inboundPacket))
			copy(originalInbound, inboundPacket)

			// Process inbound packet (should reverse translate source)
			reversed := manager.translateInboundReverse(inboundPacket, parsePacket(t, inboundPacket))
			require.True(t, reversed, "Inbound packet should be reverse translated")

			// Verify source IP was changed back to original
			srcIPAfter := netip.AddrFrom4([4]byte{inboundPacket[12], inboundPacket[13], inboundPacket[14], inboundPacket[15]})
			require.Equal(t, originalIP, srcIPAfter, "Source IP should be reverse translated")

			// Test that checksums are recalculated correctly
			if tc.protocol != layers.IPProtocolICMPv4 {
				// For TCP/UDP, verify the transport checksum was updated
				require.NotEqual(t, originalOutbound, outboundPacket, "Outbound packet should be modified")
				require.NotEqual(t, originalInbound, inboundPacket, "Inbound packet should be modified")
			}
		})
	}
}

// parsePacket helper to create a decoder for testing
func parsePacket(t testing.TB, packetData []byte) *decoder {
	t.Helper()
	d := &decoder{
		decoded: []gopacket.LayerType{},
	}
	d.parser = gopacket.NewDecodingLayerParser(
		layers.LayerTypeIPv4,
		&d.eth, &d.ip4, &d.ip6, &d.icmp4, &d.icmp6, &d.tcp, &d.udp,
	)
	d.parser.IgnoreUnsupported = true

	err := d.parser.DecodeLayers(packetData, &d.decoded)
	require.NoError(t, err)
	return d
}

// TestDNATMappingManagement tests adding/removing DNAT mappings
func TestDNATMappingManagement(t *testing.T) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger, iface.DefaultMTU)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	originalIP := netip.MustParseAddr("192.168.1.100")
	translatedIP := netip.MustParseAddr("10.0.0.100")

	// Test adding mapping
	err = manager.AddInternalDNATMapping(originalIP, translatedIP)
	require.NoError(t, err)

	// Verify mapping exists
	result, exists := manager.getDNATTranslation(originalIP)
	require.True(t, exists)
	require.Equal(t, translatedIP, result)

	// Test reverse lookup
	reverseResult, exists := manager.findReverseDNATMapping(translatedIP)
	require.True(t, exists)
	require.Equal(t, originalIP, reverseResult)

	// Test removing mapping
	err = manager.RemoveInternalDNATMapping(originalIP)
	require.NoError(t, err)

	// Verify mapping no longer exists
	_, exists = manager.getDNATTranslation(originalIP)
	require.False(t, exists)

	_, exists = manager.findReverseDNATMapping(translatedIP)
	require.False(t, exists)

	// Test error cases
	err = manager.AddInternalDNATMapping(netip.Addr{}, translatedIP)
	require.Error(t, err, "Should reject invalid original IP")

	err = manager.AddInternalDNATMapping(originalIP, netip.Addr{})
	require.Error(t, err, "Should reject invalid translated IP")

	err = manager.RemoveInternalDNATMapping(originalIP)
	require.Error(t, err, "Should error when removing non-existent mapping")
}

func TestInboundPortDNAT(t *testing.T) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger, iface.DefaultMTU)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	localAddr := netip.MustParseAddr("100.0.2.175")
	clientIP := netip.MustParseAddr("100.0.169.249")

	testCases := []struct {
		name       string
		protocol   layers.IPProtocol
		sourcePort uint16
		targetPort uint16
	}{
		{"TCP SSH", layers.IPProtocolTCP, 22, 22022},
		{"UDP DNS", layers.IPProtocolUDP, 5353, 22054},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := manager.AddInboundDNAT(localAddr, protocolToFirewall(tc.protocol), tc.sourcePort, tc.targetPort)
			require.NoError(t, err)

			inboundPacket := generateDNATTestPacket(t, clientIP, localAddr, tc.protocol, 54321, tc.sourcePort)
			d := parsePacket(t, inboundPacket)

			translated := manager.translateInboundPortDNAT(inboundPacket, d, clientIP, localAddr)
			require.True(t, translated, "Inbound packet should be translated")

			d = parsePacket(t, inboundPacket)
			var dstPort uint16
			switch tc.protocol {
			case layers.IPProtocolTCP:
				dstPort = uint16(d.tcp.DstPort)
			case layers.IPProtocolUDP:
				dstPort = uint16(d.udp.DstPort)
			}

			require.Equal(t, tc.targetPort, dstPort, "Destination port should be rewritten to target port")

			err = manager.RemoveInboundDNAT(localAddr, protocolToFirewall(tc.protocol), tc.sourcePort, tc.targetPort)
			require.NoError(t, err)
		})
	}
}

func TestInboundPortDNATNegative(t *testing.T) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger, iface.DefaultMTU)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	localAddr := netip.MustParseAddr("100.0.2.175")
	clientIP := netip.MustParseAddr("100.0.169.249")

	err = manager.AddInboundDNAT(localAddr, firewall.ProtocolTCP, 22, 22022)
	require.NoError(t, err)

	testCases := []struct {
		name     string
		protocol layers.IPProtocol
		srcIP    netip.Addr
		dstIP    netip.Addr
		srcPort  uint16
		dstPort  uint16
	}{
		{"Wrong port", layers.IPProtocolTCP, clientIP, localAddr, 54321, 80},
		{"Wrong IP", layers.IPProtocolTCP, clientIP, netip.MustParseAddr("100.64.0.99"), 54321, 22},
		{"Wrong protocol", layers.IPProtocolUDP, clientIP, localAddr, 54321, 22},
		{"ICMP", layers.IPProtocolICMPv4, clientIP, localAddr, 0, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			packet := generateDNATTestPacket(t, tc.srcIP, tc.dstIP, tc.protocol, tc.srcPort, tc.dstPort)
			d := parsePacket(t, packet)

			translated := manager.translateInboundPortDNAT(packet, d, tc.srcIP, tc.dstIP)
			require.False(t, translated, "Packet should NOT be translated for %s", tc.name)

			d = parsePacket(t, packet)
			switch tc.protocol {
			case layers.IPProtocolTCP:
				require.Equal(t, tc.dstPort, uint16(d.tcp.DstPort), "Port should remain unchanged")
			case layers.IPProtocolUDP:
				require.Equal(t, tc.dstPort, uint16(d.udp.DstPort), "Port should remain unchanged")
			}
		})
	}
}

func protocolToFirewall(proto layers.IPProtocol) firewall.Protocol {
	switch proto {
	case layers.IPProtocolTCP:
		return firewall.ProtocolTCP
	case layers.IPProtocolUDP:
		return firewall.ProtocolUDP
	default:
		return firewall.ProtocolALL
	}
}
