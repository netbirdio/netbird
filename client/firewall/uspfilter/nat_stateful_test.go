package uspfilter

import (
	"net/netip"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface/device"
)

// TestStatefulNATBidirectionalSSH tests that stateful NAT prevents interference
// when two peers try to SSH to each other simultaneously
func TestStatefulNATBidirectionalSSH(t *testing.T) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	// Define peer IPs
	peerA := netip.MustParseAddr("100.10.0.50")
	peerB := netip.MustParseAddr("100.10.0.51")

	// Add SSH port redirection rule for peer B (the target)
	err = manager.addPortRedirection(peerB, layers.LayerTypeTCP, 22, 22022)
	require.NoError(t, err)

	// Scenario: Peer A connects to Peer B on port 22 (should get NAT)
	// This simulates: ssh user@100.10.0.51
	packetAtoB := generateDNATTestPacket(t, peerA, peerB, layers.IPProtocolTCP, 54321, 22)
	translatedAtoB := manager.translateInboundPortDNAT(packetAtoB, parsePacket(t, packetAtoB))
	require.True(t, translatedAtoB, "Peer A to Peer B should be translated (NAT applied)")

	// Verify port was translated to 22022
	d := parsePacket(t, packetAtoB)
	require.Equal(t, uint16(22022), uint16(d.tcp.DstPort), "Port should be rewritten to 22022")

	// Verify NAT connection is tracked (with translated port as key)
	natConn, exists := manager.portNATTracker.getConnectionNAT(peerA, peerB, 54321, 22022)
	require.True(t, exists, "NAT connection should be tracked")
	require.Equal(t, uint16(22), natConn.originalPort, "Original port should be stored")

	// Scenario: Peer B tries to connect to Peer A on port 22 (should NOT get NAT)
	// This simulates the reverse direction to prevent interference
	packetBtoA := generateDNATTestPacket(t, peerB, peerA, layers.IPProtocolTCP, 54322, 22)
	translatedBtoA := manager.translateInboundPortDNAT(packetBtoA, parsePacket(t, packetBtoA))
	require.False(t, translatedBtoA, "Peer B to Peer A should NOT be translated (prevent interference)")

	// Verify port was NOT translated
	d2 := parsePacket(t, packetBtoA)
	require.Equal(t, uint16(22), uint16(d2.tcp.DstPort), "Port should remain 22 (no translation)")

	// Verify no reverse NAT connection is tracked
	_, reverseExists := manager.portNATTracker.getConnectionNAT(peerB, peerA, 54322, 22)
	require.False(t, reverseExists, "Reverse NAT connection should NOT be tracked")

	// Scenario: Return traffic from Peer B (SSH server) to Peer A (should be reverse translated)
	returnPacket := generateDNATTestPacket(t, peerB, peerA, layers.IPProtocolTCP, 22022, 54321)
	translatedReturn := manager.translateOutboundPortReverse(returnPacket, parsePacket(t, returnPacket))
	require.True(t, translatedReturn, "Return traffic should be reverse translated")

	// Verify return traffic port was translated back to 22
	d3 := parsePacket(t, returnPacket)
	require.Equal(t, uint16(22), uint16(d3.tcp.SrcPort), "Return traffic source port should be 22")
}

// TestStatefulNATConnectionCleanup tests connection cleanup functionality
func TestStatefulNATConnectionCleanup(t *testing.T) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	// Define peer IPs
	peerA := netip.MustParseAddr("100.10.0.50")
	peerB := netip.MustParseAddr("100.10.0.51")

	// Add SSH port redirection rules for both peers
	err = manager.addPortRedirection(peerA, layers.LayerTypeTCP, 22, 22022)
	require.NoError(t, err)
	err = manager.addPortRedirection(peerB, layers.LayerTypeTCP, 22, 22022)
	require.NoError(t, err)

	// Establish connection with NAT
	packet := generateDNATTestPacket(t, peerA, peerB, layers.IPProtocolTCP, 54321, 22)
	translated := manager.translateInboundPortDNAT(packet, parsePacket(t, packet))
	require.True(t, translated, "Initial connection should be translated")

	// Verify connection is tracked (using translated port as key)
	_, exists := manager.portNATTracker.getConnectionNAT(peerA, peerB, 54321, 22022)
	require.True(t, exists, "Connection should be tracked")

	// Clean up connection
	manager.portNATTracker.cleanupConnection(peerA, peerB, 54321)

	// Verify connection is no longer tracked (using translated port as key)
	_, stillExists := manager.portNATTracker.getConnectionNAT(peerA, peerB, 54321, 22022)
	require.False(t, stillExists, "Connection should be cleaned up")

	// Verify new connection from opposite direction now works
	reversePacket := generateDNATTestPacket(t, peerB, peerA, layers.IPProtocolTCP, 54322, 22)
	reverseTranslated := manager.translateInboundPortDNAT(reversePacket, parsePacket(t, reversePacket))
	require.True(t, reverseTranslated, "Reverse connection should now work after cleanup")
}
