package uspfilter

import (
	"net/netip"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
)

// TestPortDNATBasic tests basic port DNAT functionality
func TestPortDNATBasic(t *testing.T) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger, iface.DefaultMTU)
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
	packetAtoB := generateDNATTestPacket(t, peerA, peerB, layers.IPProtocolTCP, 54321, 22)
	d := parsePacket(t, packetAtoB)
	translatedAtoB := manager.translateInboundPortDNAT(packetAtoB, d, peerA, peerB)
	require.True(t, translatedAtoB, "Peer A to Peer B should be translated (NAT applied)")

	// Verify port was translated to 22022
	d = parsePacket(t, packetAtoB)
	require.Equal(t, uint16(22022), uint16(d.tcp.DstPort), "Port should be rewritten to 22022")

	// Scenario: Return traffic from Peer B to Peer A should NOT be translated
	// (prevents double NAT - original port stored in conntrack)
	returnPacket := generateDNATTestPacket(t, peerB, peerA, layers.IPProtocolTCP, 22022, 54321)
	d2 := parsePacket(t, returnPacket)
	translatedReturn := manager.translateInboundPortDNAT(returnPacket, d2, peerB, peerA)
	require.False(t, translatedReturn, "Return traffic from same IP should not be translated")
}

// TestPortDNATMultipleRules tests multiple port DNAT rules
func TestPortDNATMultipleRules(t *testing.T) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger, iface.DefaultMTU)
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

	// Test traffic to peer B gets translated
	packetToB := generateDNATTestPacket(t, peerA, peerB, layers.IPProtocolTCP, 54321, 22)
	d1 := parsePacket(t, packetToB)
	translatedToB := manager.translateInboundPortDNAT(packetToB, d1, peerA, peerB)
	require.True(t, translatedToB, "Traffic to peer B should be translated")
	d1 = parsePacket(t, packetToB)
	require.Equal(t, uint16(22022), uint16(d1.tcp.DstPort), "Port should be 22022")

	// Test traffic to peer A gets translated
	packetToA := generateDNATTestPacket(t, peerB, peerA, layers.IPProtocolTCP, 54322, 22)
	d2 := parsePacket(t, packetToA)
	translatedToA := manager.translateInboundPortDNAT(packetToA, d2, peerB, peerA)
	require.True(t, translatedToA, "Traffic to peer A should be translated")
	d2 = parsePacket(t, packetToA)
	require.Equal(t, uint16(22022), uint16(d2.tcp.DstPort), "Port should be 22022")
}
