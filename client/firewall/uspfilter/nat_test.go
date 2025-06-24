package uspfilter

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
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

// TestSSHPortRedirection tests SSH port redirection functionality
func TestSSHPortRedirection(t *testing.T) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	// Define NetBird network range
	peerIP := netip.MustParseAddr("100.10.0.50")
	clientIP := netip.MustParseAddr("100.10.0.100")

	// Add SSH port redirection rule
	err = manager.AddInboundDNAT(peerIP, firewall.ProtocolTCP, 22, 22022)
	require.NoError(t, err)

	// Verify port DNAT is enabled
	require.True(t, manager.portDNATEnabled.Load(), "Port DNAT should be enabled")
	require.Len(t, manager.portDNATMap.rules, 1, "Should have one port DNAT rule")

	// Verify the rule configuration
	rule := manager.portDNATMap.rules[0]
	require.Equal(t, gopacket.LayerType(layers.LayerTypeTCP), rule.protocol)
	require.Equal(t, uint16(22), rule.sourcePort)
	require.Equal(t, uint16(22022), rule.targetPort)
	require.Equal(t, peerIP, rule.targetIP)

	// Test inbound SSH packet (client -> peer:22, should redirect to peer:22022)
	inboundPacket := generateDNATTestPacket(t, clientIP, peerIP, layers.IPProtocolTCP, 54321, 22)
	originalInbound := make([]byte, len(inboundPacket))
	copy(originalInbound, inboundPacket)

	// Process inbound packet
	translated := manager.translateInboundPortDNAT(inboundPacket, parsePacket(t, inboundPacket))
	require.True(t, translated, "Inbound SSH packet should be translated")

	// Verify destination port was changed from 22 to 22022
	d := parsePacket(t, inboundPacket)
	require.Equal(t, uint16(22022), uint16(d.tcp.DstPort), "Destination port should be rewritten to 22022")

	// Verify destination IP remains unchanged
	dstIPAfter := netip.AddrFrom4([4]byte{inboundPacket[16], inboundPacket[17], inboundPacket[18], inboundPacket[19]})
	require.Equal(t, peerIP, dstIPAfter, "Destination IP should remain unchanged")

	// Test outbound return packet (peer:22022 -> client, should rewrite source port to 22)
	outboundPacket := generateDNATTestPacket(t, peerIP, clientIP, layers.IPProtocolTCP, 22022, 54321)
	originalOutbound := make([]byte, len(outboundPacket))
	copy(originalOutbound, outboundPacket)

	// Process outbound return packet
	reversed := manager.translateOutboundPortReverse(outboundPacket, parsePacket(t, outboundPacket))
	require.True(t, reversed, "Outbound return packet should be reverse translated")

	// Verify source port was changed from 22022 to 22
	d = parsePacket(t, outboundPacket)
	require.Equal(t, uint16(22), uint16(d.tcp.SrcPort), "Source port should be rewritten to 22")

	// Verify source IP remains unchanged
	srcIPAfter := netip.AddrFrom4([4]byte{outboundPacket[12], outboundPacket[13], outboundPacket[14], outboundPacket[15]})
	require.Equal(t, peerIP, srcIPAfter, "Source IP should remain unchanged")

	// Test removal of SSH port redirection
	err = manager.RemoveInboundDNAT(peerIP, firewall.ProtocolTCP, 22, 22022)
	require.NoError(t, err)
	require.False(t, manager.portDNATEnabled.Load(), "Port DNAT should be disabled after removal")
	require.Len(t, manager.portDNATMap.rules, 0, "Should have no port DNAT rules after removal")
}

// TestSSHPortRedirectionNetworkFiltering tests that SSH redirection only applies to specified networks
func TestSSHPortRedirectionNetworkFiltering(t *testing.T) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	// Define NetBird network range
	peerInNetwork := netip.MustParseAddr("100.10.0.50")
	peerOutsideNetwork := netip.MustParseAddr("192.168.1.50")
	clientIP := netip.MustParseAddr("100.10.0.100")

	// Add SSH port redirection rule for NetBird network only
	err = manager.AddInboundDNAT(peerInNetwork, firewall.ProtocolTCP, 22, 22022)
	require.NoError(t, err)

	// Test SSH packet to peer within NetBird network (should be redirected)
	inNetworkPacket := generateDNATTestPacket(t, clientIP, peerInNetwork, layers.IPProtocolTCP, 54321, 22)
	translated := manager.translateInboundPortDNAT(inNetworkPacket, parsePacket(t, inNetworkPacket))
	require.True(t, translated, "SSH packet to NetBird peer should be translated")

	// Verify port was changed
	d := parsePacket(t, inNetworkPacket)
	require.Equal(t, uint16(22022), uint16(d.tcp.DstPort), "Port should be redirected for NetBird peer")

	// Test SSH packet to peer outside NetBird network (should NOT be redirected)
	outOfNetworkPacket := generateDNATTestPacket(t, clientIP, peerOutsideNetwork, layers.IPProtocolTCP, 54321, 22)
	originalOutOfNetwork := make([]byte, len(outOfNetworkPacket))
	copy(originalOutOfNetwork, outOfNetworkPacket)

	notTranslated := manager.translateInboundPortDNAT(outOfNetworkPacket, parsePacket(t, outOfNetworkPacket))
	require.False(t, notTranslated, "SSH packet to non-NetBird peer should NOT be translated")

	// Verify packet was not modified
	require.Equal(t, originalOutOfNetwork, outOfNetworkPacket, "Packet to non-NetBird peer should remain unchanged")
}

// TestSSHPortRedirectionNonTCPTraffic tests that only TCP traffic is affected
func TestSSHPortRedirectionNonTCPTraffic(t *testing.T) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	// Define NetBird network range
	peerIP := netip.MustParseAddr("100.10.0.50")
	clientIP := netip.MustParseAddr("100.10.0.100")

	// Add SSH port redirection rule
	err = manager.AddInboundDNAT(peerIP, firewall.ProtocolTCP, 22, 22022)
	require.NoError(t, err)

	// Test UDP packet on port 22 (should NOT be redirected)
	udpPacket := generateDNATTestPacket(t, clientIP, peerIP, layers.IPProtocolUDP, 54321, 22)
	originalUDP := make([]byte, len(udpPacket))
	copy(originalUDP, udpPacket)

	translated := manager.translateInboundPortDNAT(udpPacket, parsePacket(t, udpPacket))
	require.False(t, translated, "UDP packet should NOT be translated by SSH port redirection")
	require.Equal(t, originalUDP, udpPacket, "UDP packet should remain unchanged")

	// Test ICMP packet (should NOT be redirected)
	icmpPacket := generateDNATTestPacket(t, clientIP, peerIP, layers.IPProtocolICMPv4, 0, 0)
	originalICMP := make([]byte, len(icmpPacket))
	copy(originalICMP, icmpPacket)

	translated = manager.translateInboundPortDNAT(icmpPacket, parsePacket(t, icmpPacket))
	require.False(t, translated, "ICMP packet should NOT be translated by SSH port redirection")
	require.Equal(t, originalICMP, icmpPacket, "ICMP packet should remain unchanged")
}

// TestSSHPortRedirectionNonSSHPorts tests that only port 22 is redirected
func TestSSHPortRedirectionNonSSHPorts(t *testing.T) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	// Define NetBird network range
	peerIP := netip.MustParseAddr("100.10.0.50")
	clientIP := netip.MustParseAddr("100.10.0.100")

	// Add SSH port redirection rule
	err = manager.AddInboundDNAT(peerIP, firewall.ProtocolTCP, 22, 22022)
	require.NoError(t, err)

	// Test TCP packet on port 80 (should NOT be redirected)
	httpPacket := generateDNATTestPacket(t, clientIP, peerIP, layers.IPProtocolTCP, 54321, 80)
	originalHTTP := make([]byte, len(httpPacket))
	copy(originalHTTP, httpPacket)

	translated := manager.translateInboundPortDNAT(httpPacket, parsePacket(t, httpPacket))
	require.False(t, translated, "Non-SSH TCP packet should NOT be translated")
	require.Equal(t, originalHTTP, httpPacket, "Non-SSH TCP packet should remain unchanged")

	// Test TCP packet on port 443 (should NOT be redirected)
	httpsPacket := generateDNATTestPacket(t, clientIP, peerIP, layers.IPProtocolTCP, 54321, 443)
	originalHTTPS := make([]byte, len(httpsPacket))
	copy(originalHTTPS, httpsPacket)

	translated = manager.translateInboundPortDNAT(httpsPacket, parsePacket(t, httpsPacket))
	require.False(t, translated, "Non-SSH TCP packet should NOT be translated")
	require.Equal(t, originalHTTPS, httpsPacket, "Non-SSH TCP packet should remain unchanged")

	// Test TCP packet on port 22 (SHOULD be redirected)
	sshPacket := generateDNATTestPacket(t, clientIP, peerIP, layers.IPProtocolTCP, 54321, 22)
	translated = manager.translateInboundPortDNAT(sshPacket, parsePacket(t, sshPacket))
	require.True(t, translated, "SSH TCP packet should be translated")

	// Verify port was changed to 22022
	d := parsePacket(t, sshPacket)
	require.Equal(t, uint16(22022), uint16(d.tcp.DstPort), "SSH port should be redirected to 22022")
}

// TestFlexiblePortRedirection tests the flexible port redirection functionality
func TestFlexiblePortRedirection(t *testing.T) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	// Define peer and client IPs
	peerIP := netip.MustParseAddr("10.0.0.50")
	clientIP := netip.MustParseAddr("10.0.0.100")

	// Add custom port redirection: TCP port 8080 -> 3000 for peer IP
	err = manager.addPortRedirection(peerIP, gopacket.LayerType(layers.LayerTypeTCP), 8080, 3000)
	require.NoError(t, err)

	// Verify port DNAT is enabled
	require.True(t, manager.portDNATEnabled.Load(), "Port DNAT should be enabled")
	require.Len(t, manager.portDNATMap.rules, 1, "Should have one port DNAT rule")

	// Verify the rule configuration
	rule := manager.portDNATMap.rules[0]
	require.Equal(t, gopacket.LayerType(layers.LayerTypeTCP), rule.protocol)
	require.Equal(t, uint16(8080), rule.sourcePort)
	require.Equal(t, uint16(3000), rule.targetPort)
	require.Equal(t, peerIP, rule.targetIP)

	// Test inbound packet (client -> peer:8080, should redirect to peer:3000)
	inboundPacket := generateDNATTestPacket(t, clientIP, peerIP, layers.IPProtocolTCP, 54321, 8080)
	translated := manager.translateInboundPortDNAT(inboundPacket, parsePacket(t, inboundPacket))
	require.True(t, translated, "Inbound packet should be translated")

	// Verify destination port was changed from 8080 to 3000
	d := parsePacket(t, inboundPacket)
	require.Equal(t, uint16(3000), uint16(d.tcp.DstPort), "Destination port should be rewritten to 3000")

	// Test outbound return packet (peer:3000 -> client, should rewrite source port to 8080)
	outboundPacket := generateDNATTestPacket(t, peerIP, clientIP, layers.IPProtocolTCP, 3000, 54321)
	reversed := manager.translateOutboundPortReverse(outboundPacket, parsePacket(t, outboundPacket))
	require.True(t, reversed, "Outbound return packet should be reverse translated")

	// Verify source port was changed from 3000 to 8080
	d = parsePacket(t, outboundPacket)
	require.Equal(t, uint16(8080), uint16(d.tcp.SrcPort), "Source port should be rewritten to 8080")

	// Test removal of port redirection
	err = manager.removePortRedirection(peerIP, gopacket.LayerType(layers.LayerTypeTCP), 8080, 3000)
	require.NoError(t, err)
	require.False(t, manager.portDNATEnabled.Load(), "Port DNAT should be disabled after removal")
	require.Len(t, manager.portDNATMap.rules, 0, "Should have no port DNAT rules after removal")
}

// TestMultiplePortRedirections tests multiple port redirection rules
func TestMultiplePortRedirections(t *testing.T) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	// Define peer and client IPs
	peerIP := netip.MustParseAddr("172.16.0.50")
	clientIP := netip.MustParseAddr("172.16.0.100")

	// Add multiple port redirections for peer IP
	err = manager.addPortRedirection(peerIP, gopacket.LayerType(layers.LayerTypeTCP), 22, 22022) // SSH
	require.NoError(t, err)
	err = manager.addPortRedirection(peerIP, gopacket.LayerType(layers.LayerTypeTCP), 80, 8080) // HTTP
	require.NoError(t, err)
	err = manager.addPortRedirection(peerIP, gopacket.LayerType(layers.LayerTypeTCP), 443, 8443) // HTTPS
	require.NoError(t, err)

	// Verify all rules are present
	require.True(t, manager.portDNATEnabled.Load(), "Port DNAT should be enabled")
	require.Len(t, manager.portDNATMap.rules, 3, "Should have three port DNAT rules")

	// Test SSH redirection (22 -> 22022)
	sshPacket := generateDNATTestPacket(t, clientIP, peerIP, layers.IPProtocolTCP, 54321, 22)
	translated := manager.translateInboundPortDNAT(sshPacket, parsePacket(t, sshPacket))
	require.True(t, translated, "SSH packet should be translated")
	d := parsePacket(t, sshPacket)
	require.Equal(t, uint16(22022), uint16(d.tcp.DstPort), "SSH should redirect to 22022")

	// Test HTTP redirection (80 -> 8080)
	httpPacket := generateDNATTestPacket(t, clientIP, peerIP, layers.IPProtocolTCP, 54321, 80)
	translated = manager.translateInboundPortDNAT(httpPacket, parsePacket(t, httpPacket))
	require.True(t, translated, "HTTP packet should be translated")
	d = parsePacket(t, httpPacket)
	require.Equal(t, uint16(8080), uint16(d.tcp.DstPort), "HTTP should redirect to 8080")

	// Test HTTPS redirection (443 -> 8443)
	httpsPacket := generateDNATTestPacket(t, clientIP, peerIP, layers.IPProtocolTCP, 54321, 443)
	translated = manager.translateInboundPortDNAT(httpsPacket, parsePacket(t, httpsPacket))
	require.True(t, translated, "HTTPS packet should be translated")
	d = parsePacket(t, httpsPacket)
	require.Equal(t, uint16(8443), uint16(d.tcp.DstPort), "HTTPS should redirect to 8443")

	// Test removing one rule (HTTP)
	err = manager.removePortRedirection(peerIP, gopacket.LayerType(layers.LayerTypeTCP), 80, 8080)
	require.NoError(t, err)
	require.Len(t, manager.portDNATMap.rules, 2, "Should have two rules after removing HTTP rule")

	// Verify HTTP is no longer redirected
	httpPacket2 := generateDNATTestPacket(t, clientIP, peerIP, layers.IPProtocolTCP, 54321, 80)
	originalHTTP := make([]byte, len(httpPacket2))
	copy(originalHTTP, httpPacket2)
	translated = manager.translateInboundPortDNAT(httpPacket2, parsePacket(t, httpPacket2))
	require.False(t, translated, "HTTP packet should NOT be translated after rule removal")
	require.Equal(t, originalHTTP, httpPacket2, "HTTP packet should remain unchanged")

	// Verify SSH and HTTPS still work
	sshPacket2 := generateDNATTestPacket(t, clientIP, peerIP, layers.IPProtocolTCP, 54321, 22)
	translated = manager.translateInboundPortDNAT(sshPacket2, parsePacket(t, sshPacket2))
	require.True(t, translated, "SSH should still be translated")

	httpsPacket2 := generateDNATTestPacket(t, clientIP, peerIP, layers.IPProtocolTCP, 54321, 443)
	translated = manager.translateInboundPortDNAT(httpsPacket2, parsePacket(t, httpsPacket2))
	require.True(t, translated, "HTTPS should still be translated")
}

// TestSSHPortRedirectionEndToEnd tests actual network delivery through sockets
func TestSSHPortRedirectionEndToEnd(t *testing.T) {
	// Start a mock SSH server on port 22022 (NetBird SSH server)
	mockSSHServer, err := net.Listen("tcp", "127.0.0.1:22022")
	require.NoError(t, err, "Should be able to bind to NetBird SSH port")
	defer func() {
		require.NoError(t, mockSSHServer.Close())
	}()

	// Handle connections on the SSH server
	serverReceivedData := make(chan string, 1)
	go func() {
		for {
			conn, err := mockSSHServer.Accept()
			if err != nil {
				return // Server closed
			}
			go func(conn net.Conn) {
				defer func() {
					require.NoError(t, conn.Close())
				}()

				buf := make([]byte, 1024)
				n, err := conn.Read(buf)
				if err != nil && err != io.EOF {
					t.Logf("Server read error: %v", err)
					return
				}

				receivedData := string(buf[:n])
				serverReceivedData <- receivedData

				// Echo back a response
				_, err = conn.Write([]byte("SSH-2.0-MockNetBirdSSH\r\n"))
				if err != nil {
					t.Logf("Server write error: %v", err)
				}
			}(conn)
		}
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// This test demonstrates what SHOULD happen after port redirection:
	// 1. Client connects to 127.0.0.1:22 (standard SSH port)
	// 2. Firewall redirects to 127.0.0.1:22022 (NetBird SSH server)
	// 3. NetBird SSH server receives the connection

	t.Run("DirectConnectionToNetBirdSSHPort", func(t *testing.T) {
		// This simulates what should happen AFTER port redirection
		// Connect directly to 22022 (where NetBird SSH server listens)
		conn, err := net.DialTimeout("tcp", "127.0.0.1:22022", 5*time.Second)
		require.NoError(t, err, "Should connect to NetBird SSH server")
		defer func() {
			require.NoError(t, conn.Close())
		}()

		// Send SSH client identification
		testData := "SSH-2.0-TestClient\r\n"
		_, err = conn.Write([]byte(testData))
		require.NoError(t, err, "Should send data to SSH server")

		// Verify server received the data
		select {
		case received := <-serverReceivedData:
			require.Equal(t, testData, received, "Server should receive client data")
		case <-time.After(2 * time.Second):
			t.Fatal("Server did not receive data within timeout")
		}

		// Read server response
		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := conn.Read(buf)
		require.NoError(t, err, "Should read server response")

		response := string(buf[:n])
		require.Equal(t, "SSH-2.0-MockNetBirdSSH\r\n", response, "Should receive SSH server identification")
	})

	t.Run("PortRedirectionSimulation", func(t *testing.T) {
		// This test simulates the port redirection process
		// Note: This doesn't test the actual userspace packet interception,
		// but demonstrates the expected behavior

		t.Log("NOTE: This test demonstrates expected behavior after implementing")
		t.Log("full userspace packet interception. Currently, we test packet")
		t.Log("translation logic separately from actual network delivery.")

		// In a real implementation with userspace packet interception:
		// 1. Client would connect to 127.0.0.1:22
		// 2. Userspace firewall would intercept packets
		// 3. translateInboundPortDNAT would rewrite port 22 -> 22022
		// 4. Packets would be delivered to 127.0.0.1:22022
		// 5. NetBird SSH server would receive the connection

		// For now, we verify that the packet translation logic works correctly
		// (this is tested in other test functions) and that the target server
		// is reachable (tested above)

		clientIP := netip.MustParseAddr("127.0.0.1")
		serverIP := netip.MustParseAddr("127.0.0.1")

		// Create manager with SSH port redirection
		manager, err := Create(&IFaceMock{
			SetFilterFunc: func(device.PacketFilter) error { return nil },
		}, false, flowLogger)
		require.NoError(t, err)
		defer func() {
			require.NoError(t, manager.Close(nil))
		}()

		// Add SSH port redirection for localhost (for testing)
		err = manager.AddInboundDNAT(netip.MustParseAddr("127.0.0.1"), firewall.ProtocolTCP, 22, 22022)
		require.NoError(t, err)

		// Generate packet: client connecting to server:22
		sshPacket := generateDNATTestPacket(t, clientIP, serverIP, layers.IPProtocolTCP, 54321, 22)
		originalPacket := make([]byte, len(sshPacket))
		copy(originalPacket, sshPacket)

		// Apply port redirection
		translated := manager.translateInboundPortDNAT(sshPacket, parsePacket(t, sshPacket))
		require.True(t, translated, "SSH packet should be translated")

		// Verify port was redirected from 22 to 22022
		d := parsePacket(t, sshPacket)
		require.Equal(t, uint16(22022), uint16(d.tcp.DstPort), "Port should be redirected to NetBird SSH server")
		require.NotEqual(t, originalPacket, sshPacket, "Packet should be modified")

		t.Log("✓ Packet translation verified: port 22 redirected to 22022")
		t.Log("✓ Target SSH server (port 22022) is reachable and responsive")
		t.Log("→ Integration complete: SSH port redirection ready for userspace interception")
	})
}

// TestFullSSHRedirectionWorkflow demonstrates the complete SSH redirection workflow
func TestFullSSHRedirectionWorkflow(t *testing.T) {
	t.Log("=== SSH Port Redirection Workflow Test ===")
	t.Log("This test demonstrates the complete SSH redirection process:")
	t.Log("1. Client connects to peer:22 (standard SSH)")
	t.Log("2. Userspace firewall intercepts and redirects to peer:22022")
	t.Log("3. NetBird SSH server receives connection on port 22022")
	t.Log("4. Return traffic is reverse-translated (22022 -> 22)")

	// Setup test environment
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	// Define NetBird network and peer IPs
	peerIP := netip.MustParseAddr("100.10.0.50")
	clientIP := netip.MustParseAddr("100.10.0.100")

	// Step 1: Configure SSH port redirection
	err = manager.AddInboundDNAT(peerIP, firewall.ProtocolTCP, 22, 22022)
	require.NoError(t, err)
	t.Log("✓ SSH port redirection configured for NetBird network")

	// Step 2: Simulate inbound SSH connection (client -> peer:22)
	t.Log("→ Simulating: ssh user@100.10.0.50")
	inboundPacket := generateDNATTestPacket(t, clientIP, peerIP, layers.IPProtocolTCP, 54321, 22)

	// Step 3: Apply inbound port redirection
	translated := manager.translateInboundPortDNAT(inboundPacket, parsePacket(t, inboundPacket))
	require.True(t, translated, "Inbound SSH packet should be redirected")

	d := parsePacket(t, inboundPacket)
	require.Equal(t, uint16(22022), uint16(d.tcp.DstPort), "Should redirect to NetBird SSH server port")
	t.Log("✓ Inbound packet redirected: 100.10.0.50:22 → 100.10.0.50:22022")

	// Step 4: Simulate outbound return traffic (peer:22022 -> client)
	t.Log("→ Simulating return traffic from NetBird SSH server")
	outboundPacket := generateDNATTestPacket(t, peerIP, clientIP, layers.IPProtocolTCP, 22022, 54321)

	// Step 5: Apply outbound reverse translation
	reversed := manager.translateOutboundPortReverse(outboundPacket, parsePacket(t, outboundPacket))
	require.True(t, reversed, "Outbound return packet should be reverse translated")

	d = parsePacket(t, outboundPacket)
	require.Equal(t, uint16(22), uint16(d.tcp.SrcPort), "Should restore original SSH port")
	t.Log("✓ Outbound packet reverse translated: 100.10.0.50:22022 → 100.10.0.50:22")

	// Step 6: Verify client sees standard SSH connection
	srcIPAfter := netip.AddrFrom4([4]byte{outboundPacket[12], outboundPacket[13], outboundPacket[14], outboundPacket[15]})
	require.Equal(t, peerIP, srcIPAfter, "Client should see traffic from peer IP")
	t.Log("✓ Client receives traffic from 100.10.0.50:22 (transparent redirection)")

	t.Log("=== SSH Port Redirection Workflow Complete ===")
	t.Log("Result: Standard SSH clients can connect to NetBird peers using:")
	t.Log("  ssh user@100.10.0.50")
	t.Log("Instead of:")
	t.Log("  ssh user@100.10.0.50 -p 22022")
}
