package uspfilter

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
)

// BenchmarkDNATTranslation measures the performance of DNAT operations
func BenchmarkDNATTranslation(b *testing.B) {
	scenarios := []struct {
		name        string
		proto       layers.IPProtocol
		setupDNAT   bool
		description string
	}{
		{
			name:        "tcp_with_dnat",
			proto:       layers.IPProtocolTCP,
			setupDNAT:   true,
			description: "TCP packet with DNAT translation enabled",
		},
		{
			name:        "tcp_without_dnat",
			proto:       layers.IPProtocolTCP,
			setupDNAT:   false,
			description: "TCP packet without DNAT (baseline)",
		},
		{
			name:        "udp_with_dnat",
			proto:       layers.IPProtocolUDP,
			setupDNAT:   true,
			description: "UDP packet with DNAT translation enabled",
		},
		{
			name:        "udp_without_dnat",
			proto:       layers.IPProtocolUDP,
			setupDNAT:   false,
			description: "UDP packet without DNAT (baseline)",
		},
		{
			name:        "icmp_with_dnat",
			proto:       layers.IPProtocolICMPv4,
			setupDNAT:   true,
			description: "ICMP packet with DNAT translation enabled",
		},
		{
			name:        "icmp_without_dnat",
			proto:       layers.IPProtocolICMPv4,
			setupDNAT:   false,
			description: "ICMP packet without DNAT (baseline)",
		},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			manager, err := Create(&IFaceMock{
				SetFilterFunc: func(device.PacketFilter) error { return nil },
			}, false, flowLogger, iface.DefaultMTU)
			require.NoError(b, err)
			defer func() {
				require.NoError(b, manager.Close(nil))
			}()

			// Set logger to error level to reduce noise during benchmarking
			manager.SetLogLevel(log.ErrorLevel)
			defer func() {
				// Restore to info level after benchmark
				manager.SetLogLevel(log.InfoLevel)
			}()

			// Setup DNAT mapping if needed
			originalIP := netip.MustParseAddr("192.168.1.100")
			translatedIP := netip.MustParseAddr("10.0.0.100")

			if sc.setupDNAT {
				err := manager.AddInternalDNATMapping(originalIP, translatedIP)
				require.NoError(b, err)
			}

			// Create test packets
			srcIP := netip.MustParseAddr("172.16.0.1")
			outboundPacket := generateDNATTestPacket(b, srcIP, originalIP, sc.proto, 12345, 80)

			// Pre-establish connection for reverse DNAT test
			if sc.setupDNAT {
				manager.filterOutbound(outboundPacket, 0)
			}

			b.ResetTimer()

			// Benchmark outbound DNAT translation
			b.Run("outbound", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					// Create fresh packet each time since translation modifies it
					packet := generateDNATTestPacket(b, srcIP, originalIP, sc.proto, 12345, 80)
					manager.filterOutbound(packet, 0)
				}
			})

			// Benchmark inbound reverse DNAT translation
			if sc.setupDNAT {
				b.Run("inbound_reverse", func(b *testing.B) {
					for i := 0; i < b.N; i++ {
						// Create fresh packet each time since translation modifies it
						packet := generateDNATTestPacket(b, translatedIP, srcIP, sc.proto, 80, 12345)
						manager.filterInbound(packet, 0)
					}
				})
			}
		})
	}
}

// BenchmarkDNATConcurrency tests DNAT performance under concurrent load
func BenchmarkDNATConcurrency(b *testing.B) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger, iface.DefaultMTU)
	require.NoError(b, err)
	defer func() {
		require.NoError(b, manager.Close(nil))
	}()

	// Set logger to error level to reduce noise during benchmarking
	manager.SetLogLevel(log.ErrorLevel)
	defer func() {
		// Restore to info level after benchmark
		manager.SetLogLevel(log.InfoLevel)
	}()

	// Setup multiple DNAT mappings
	numMappings := 100
	originalIPs := make([]netip.Addr, numMappings)
	translatedIPs := make([]netip.Addr, numMappings)

	for i := 0; i < numMappings; i++ {
		originalIPs[i] = netip.MustParseAddr(fmt.Sprintf("192.168.%d.%d", (i/254)+1, (i%254)+1))
		translatedIPs[i] = netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", (i/254)+1, (i%254)+1))
		err := manager.AddInternalDNATMapping(originalIPs[i], translatedIPs[i])
		require.NoError(b, err)
	}

	srcIP := netip.MustParseAddr("172.16.0.1")

	// Pre-generate packets
	outboundPackets := make([][]byte, numMappings)
	inboundPackets := make([][]byte, numMappings)
	for i := 0; i < numMappings; i++ {
		outboundPackets[i] = generateDNATTestPacket(b, srcIP, originalIPs[i], layers.IPProtocolTCP, 12345, 80)
		inboundPackets[i] = generateDNATTestPacket(b, translatedIPs[i], srcIP, layers.IPProtocolTCP, 80, 12345)
		// Establish connections
		manager.filterOutbound(outboundPackets[i], 0)
	}

	b.ResetTimer()

	b.Run("concurrent_outbound", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				idx := i % numMappings
				packet := generateDNATTestPacket(b, srcIP, originalIPs[idx], layers.IPProtocolTCP, 12345, 80)
				manager.filterOutbound(packet, 0)
				i++
			}
		})
	})

	b.Run("concurrent_inbound", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			i := 0
			for pb.Next() {
				idx := i % numMappings
				packet := generateDNATTestPacket(b, translatedIPs[idx], srcIP, layers.IPProtocolTCP, 80, 12345)
				manager.filterInbound(packet, 0)
				i++
			}
		})
	})
}

// BenchmarkDNATScaling tests how DNAT performance scales with number of mappings
func BenchmarkDNATScaling(b *testing.B) {
	mappingCounts := []int{1, 10, 100, 1000}

	for _, count := range mappingCounts {
		b.Run(fmt.Sprintf("mappings_%d", count), func(b *testing.B) {
			manager, err := Create(&IFaceMock{
				SetFilterFunc: func(device.PacketFilter) error { return nil },
			}, false, flowLogger, iface.DefaultMTU)
			require.NoError(b, err)
			defer func() {
				require.NoError(b, manager.Close(nil))
			}()

			// Set logger to error level to reduce noise during benchmarking
			manager.SetLogLevel(log.ErrorLevel)
			defer func() {
				// Restore to info level after benchmark
				manager.SetLogLevel(log.InfoLevel)
			}()

			// Setup DNAT mappings
			for i := 0; i < count; i++ {
				originalIP := netip.MustParseAddr(fmt.Sprintf("192.168.%d.%d", (i/254)+1, (i%254)+1))
				translatedIP := netip.MustParseAddr(fmt.Sprintf("10.0.%d.%d", (i/254)+1, (i%254)+1))
				err := manager.AddInternalDNATMapping(originalIP, translatedIP)
				require.NoError(b, err)
			}

			// Test with the last mapping added (worst case for lookup)
			srcIP := netip.MustParseAddr("172.16.0.1")
			lastOriginal := netip.MustParseAddr(fmt.Sprintf("192.168.%d.%d", ((count-1)/254)+1, ((count-1)%254)+1))

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				packet := generateDNATTestPacket(b, srcIP, lastOriginal, layers.IPProtocolTCP, 12345, 80)
				manager.filterOutbound(packet, 0)
			}
		})
	}
}

// generateDNATTestPacket creates a test packet for DNAT benchmarking
func generateDNATTestPacket(tb testing.TB, srcIP, dstIP netip.Addr, proto layers.IPProtocol, srcPort, dstPort uint16) []byte {
	tb.Helper()

	ipv4 := &layers.IPv4{
		TTL:      64,
		Version:  4,
		SrcIP:    srcIP.AsSlice(),
		DstIP:    dstIP.AsSlice(),
		Protocol: proto,
	}

	var transportLayer gopacket.SerializableLayer
	switch proto {
	case layers.IPProtocolTCP:
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
			SYN:     true,
		}
		require.NoError(tb, tcp.SetNetworkLayerForChecksum(ipv4))
		transportLayer = tcp
	case layers.IPProtocolUDP:
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		require.NoError(tb, udp.SetNetworkLayerForChecksum(ipv4))
		transportLayer = udp
	case layers.IPProtocolICMPv4:
		icmp := &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
		}
		transportLayer = icmp
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts, ipv4, transportLayer, gopacket.Payload("test"))
	require.NoError(tb, err)
	return buf.Bytes()
}

// BenchmarkChecksumUpdate specifically benchmarks checksum calculation performance
func BenchmarkChecksumUpdate(b *testing.B) {
	// Create test data for checksum calculations
	testData := make([]byte, 64) // Typical packet size for checksum testing
	for i := range testData {
		testData[i] = byte(i)
	}

	b.Run("ipv4_checksum", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = ipv4Checksum(testData[:20]) // IPv4 header is typically 20 bytes
		}
	})

	b.Run("icmp_checksum", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = icmpChecksum(testData)
		}
	})

	b.Run("incremental_update", func(b *testing.B) {
		oldBytes := []byte{192, 168, 1, 100}
		newBytes := []byte{10, 0, 0, 100}
		oldChecksum := uint16(0x1234)

		for i := 0; i < b.N; i++ {
			_ = incrementalUpdate(oldChecksum, oldBytes, newBytes)
		}
	})
}

// BenchmarkDNATMemoryAllocations checks for memory allocations in DNAT operations
func BenchmarkDNATMemoryAllocations(b *testing.B) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger, iface.DefaultMTU)
	require.NoError(b, err)
	defer func() {
		require.NoError(b, manager.Close(nil))
	}()

	// Set logger to error level to reduce noise during benchmarking
	manager.SetLogLevel(log.ErrorLevel)
	defer func() {
		// Restore to info level after benchmark
		manager.SetLogLevel(log.InfoLevel)
	}()

	originalIP := netip.MustParseAddr("192.168.1.100")
	translatedIP := netip.MustParseAddr("10.0.0.100")
	srcIP := netip.MustParseAddr("172.16.0.1")

	err = manager.AddInternalDNATMapping(originalIP, translatedIP)
	require.NoError(b, err)

	packet := generateDNATTestPacket(b, srcIP, originalIP, layers.IPProtocolTCP, 12345, 80)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Create fresh packet each time to isolate allocation testing
		testPacket := make([]byte, len(packet))
		copy(testPacket, packet)

		// Parse the packet fresh each time to get a clean decoder
		d := &decoder{decoded: []gopacket.LayerType{}}
		d.parser = gopacket.NewDecodingLayerParser(
			layers.LayerTypeIPv4,
			&d.eth, &d.ip4, &d.ip6, &d.icmp4, &d.icmp6, &d.tcp, &d.udp,
		)
		d.parser.IgnoreUnsupported = true
		err = d.parser.DecodeLayers(testPacket, &d.decoded)
		assert.NoError(b, err)

		manager.translateOutboundDNAT(testPacket, d)
	}
}

// BenchmarkDirectIPExtraction tests the performance improvement of direct IP extraction
func BenchmarkDirectIPExtraction(b *testing.B) {
	// Create a test packet
	srcIP := netip.MustParseAddr("172.16.0.1")
	dstIP := netip.MustParseAddr("192.168.1.100")
	packet := generateDNATTestPacket(b, srcIP, dstIP, layers.IPProtocolTCP, 12345, 80)

	b.Run("direct_byte_access", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			// Direct extraction from packet bytes
			_ = netip.AddrFrom4([4]byte{packet[16], packet[17], packet[18], packet[19]})
		}
	})

	b.Run("decoder_extraction", func(b *testing.B) {
		// Create decoder once for comparison
		d := &decoder{decoded: []gopacket.LayerType{}}
		d.parser = gopacket.NewDecodingLayerParser(
			layers.LayerTypeIPv4,
			&d.eth, &d.ip4, &d.ip6, &d.icmp4, &d.icmp6, &d.tcp, &d.udp,
		)
		d.parser.IgnoreUnsupported = true
		err := d.parser.DecodeLayers(packet, &d.decoded)
		assert.NoError(b, err)

		for i := 0; i < b.N; i++ {
			// Extract using decoder (traditional method)
			dst, _ := netip.AddrFromSlice(d.ip4.DstIP)
			_ = dst
		}
	})
}

// BenchmarkChecksumOptimizations compares optimized vs standard checksum implementations
func BenchmarkChecksumOptimizations(b *testing.B) {
	// Create test IPv4 header (20 bytes)
	header := make([]byte, 20)
	for i := range header {
		header[i] = byte(i)
	}
	// Clear checksum field
	header[10] = 0
	header[11] = 0

	b.Run("optimized_ipv4_checksum", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = ipv4Checksum(header)
		}
	})

	// Test incremental checksum updates
	oldIP := []byte{192, 168, 1, 100}
	newIP := []byte{10, 0, 0, 100}
	oldChecksum := uint16(0x1234)

	b.Run("optimized_incremental_update", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = incrementalUpdate(oldChecksum, oldIP, newIP)
		}
	})
}

// BenchmarkPortDNAT measures the performance of port DNAT operations
func BenchmarkPortDNAT(b *testing.B) {
	scenarios := []struct {
		name         string
		proto        layers.IPProtocol
		setupDNAT    bool
		useMatchPort bool
		description  string
	}{
		{
			name:         "tcp_inbound_dnat_match",
			proto:        layers.IPProtocolTCP,
			setupDNAT:    true,
			useMatchPort: true,
			description:  "TCP inbound port DNAT translation (22 → 22022)",
		},
		{
			name:         "tcp_inbound_dnat_nomatch",
			proto:        layers.IPProtocolTCP,
			setupDNAT:    true,
			useMatchPort: false,
			description:  "TCP inbound with DNAT configured but no port match",
		},
		{
			name:         "tcp_inbound_no_dnat",
			proto:        layers.IPProtocolTCP,
			setupDNAT:    false,
			useMatchPort: false,
			description:  "TCP inbound without DNAT (baseline)",
		},
		{
			name:         "udp_inbound_dnat_match",
			proto:        layers.IPProtocolUDP,
			setupDNAT:    true,
			useMatchPort: true,
			description:  "UDP inbound port DNAT translation (5353 → 22054)",
		},
		{
			name:         "udp_inbound_dnat_nomatch",
			proto:        layers.IPProtocolUDP,
			setupDNAT:    true,
			useMatchPort: false,
			description:  "UDP inbound with DNAT configured but no port match",
		},
		{
			name:         "udp_inbound_no_dnat",
			proto:        layers.IPProtocolUDP,
			setupDNAT:    false,
			useMatchPort: false,
			description:  "UDP inbound without DNAT (baseline)",
		},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			manager, err := Create(&IFaceMock{
				SetFilterFunc: func(device.PacketFilter) error { return nil },
			}, false, flowLogger, iface.DefaultMTU)
			require.NoError(b, err)
			defer func() {
				require.NoError(b, manager.Close(nil))
			}()

			// Set logger to error level to reduce noise during benchmarking
			manager.SetLogLevel(log.ErrorLevel)
			defer func() {
				// Restore to info level after benchmark
				manager.SetLogLevel(log.InfoLevel)
			}()

			localAddr := netip.MustParseAddr("100.0.2.175")
			clientIP := netip.MustParseAddr("100.0.169.249")

			var origPort, targetPort, testPort uint16
			if sc.proto == layers.IPProtocolTCP {
				origPort, targetPort = 22, 22022
			} else {
				origPort, targetPort = 5353, 22054
			}

			if sc.useMatchPort {
				testPort = origPort
			} else {
				testPort = 443 // Different port
			}

			// Setup port DNAT mapping if needed
			if sc.setupDNAT {
				err := manager.AddInboundDNAT(localAddr, protocolToFirewall(sc.proto), origPort, targetPort)
				require.NoError(b, err)
			}

			// Pre-establish inbound connection for outbound reverse test
			if sc.setupDNAT && sc.useMatchPort {
				inboundPacket := generateDNATTestPacket(b, clientIP, localAddr, sc.proto, 54321, origPort)
				manager.filterInbound(inboundPacket, 0)
			}

			b.ResetTimer()
			b.ReportAllocs()

			// Benchmark inbound DNAT translation
			b.Run("inbound", func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					// Create fresh packet each time
					packet := generateDNATTestPacket(b, clientIP, localAddr, sc.proto, 54321, testPort)
					manager.filterInbound(packet, 0)
				}
			})

			// Benchmark outbound reverse DNAT translation (only if DNAT is set up and port matches)
			if sc.setupDNAT && sc.useMatchPort {
				b.Run("outbound_reverse", func(b *testing.B) {
					for i := 0; i < b.N; i++ {
						// Create fresh return packet (from target port)
						packet := generateDNATTestPacket(b, localAddr, clientIP, sc.proto, targetPort, 54321)
						manager.filterOutbound(packet, 0)
					}
				})
			}
		})
	}
}
