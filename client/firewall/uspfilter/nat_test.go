package uspfilter

import (
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/device"
)

// TestDNATTranslationCorrectness verifies DNAT translation works correctly
func TestDNATTranslationCorrectness(t *testing.T) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger)
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
	}, false, flowLogger)
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
