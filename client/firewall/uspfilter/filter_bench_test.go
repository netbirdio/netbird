//go:build uspbench

package uspfilter

import (
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
)

// generateRandomIPs generates n different random IPs in the 100.64.0.0/10 range
func generateRandomIPs(n int) []net.IP {
	ips := make([]net.IP, n)
	seen := make(map[string]bool)

	for i := 0; i < n; {
		ip := make(net.IP, 4)
		ip[0] = 100
		ip[1] = byte(64 + rand.Intn(63)) // 64-126
		ip[2] = byte(rand.Intn(256))
		ip[3] = byte(1 + rand.Intn(254)) // avoid .0 and .255

		key := ip.String()
		if !seen[key] {
			ips[i] = ip
			seen[key] = true
			i++
		}
	}
	return ips
}

func generatePacket(b *testing.B, srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol layers.IPProtocol) []byte {
	b.Helper()

	ipv4 := &layers.IPv4{
		TTL:      64,
		Version:  4,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: protocol,
	}

	var transportLayer gopacket.SerializableLayer
	switch protocol {
	case layers.IPProtocolTCP:
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
			SYN:     true,
		}
		require.NoError(b, tcp.SetNetworkLayerForChecksum(ipv4))
		transportLayer = tcp
	case layers.IPProtocolUDP:
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		require.NoError(b, udp.SetNetworkLayerForChecksum(ipv4))
		transportLayer = udp
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	err := gopacket.SerializeLayers(buf, opts, ipv4, transportLayer, gopacket.Payload("test"))
	require.NoError(b, err)
	return buf.Bytes()
}

// BenchmarkCoreFiltering focuses on the essential performance comparisons between
// stateful and stateless filtering approaches
func BenchmarkCoreFiltering(b *testing.B) {
	scenarios := []struct {
		name      string
		stateful  bool
		setupFunc func(*Manager)
		desc      string
	}{
		{
			name:     "stateless_single_allow_all",
			stateful: false,
			setupFunc: func(m *Manager) {
				// Single rule allowing all traffic
				_, err := m.AddPeerFiltering(nil, net.ParseIP("0.0.0.0"), fw.ProtocolALL, nil, nil, fw.ActionAccept, "")
				require.NoError(b, err)
			},
			desc: "Baseline: Single 'allow all' rule without connection tracking",
		},
		{
			name:     "stateful_no_rules",
			stateful: true,
			setupFunc: func(m *Manager) {
				// No explicit rules - rely purely on connection tracking
			},
			desc: "Pure connection tracking without any rules",
		},
		{
			name:     "stateless_explicit_return",
			stateful: false,
			setupFunc: func(m *Manager) {
				// Add explicit rules matching return traffic pattern
				for i := 0; i < 1000; i++ { // Simulate realistic ruleset size
					ip := generateRandomIPs(1)[0]
					_, err := m.AddPeerFiltering(
						nil,
						ip,
						fw.ProtocolTCP,
						&fw.Port{Values: []uint16{uint16(1024 + i)}},
						&fw.Port{Values: []uint16{80}},
						fw.ActionAccept,
						"",
					)
					require.NoError(b, err)
				}
			},
			desc: "Explicit rules matching return traffic patterns without state",
		},
		{
			name:     "stateful_with_established",
			stateful: true,
			setupFunc: func(m *Manager) {
				// Add some basic rules but rely on state for established connections
				_, err := m.AddPeerFiltering(
					nil,
					net.ParseIP("0.0.0.0"),
					fw.ProtocolTCP,
					nil,
					nil,
					fw.ActionDrop,
					"",
				)
				require.NoError(b, err)
			},
			desc: "Connection tracking with established connections",
		},
	}

	// Test both TCP and UDP
	protocols := []struct {
		name  string
		proto layers.IPProtocol
	}{
		{"TCP", layers.IPProtocolTCP},
		{"UDP", layers.IPProtocolUDP},
	}

	for _, sc := range scenarios {
		for _, proto := range protocols {
			b.Run(fmt.Sprintf("%s_%s", sc.name, proto.name), func(b *testing.B) {
				// Configure stateful/stateless mode
				if !sc.stateful {
					require.NoError(b, os.Setenv("NB_DISABLE_CONNTRACK", "1"))
				} else {
					require.NoError(b, os.Setenv("NB_CONNTRACK_TIMEOUT", "1m"))
				}

				// Create manager and basic setup
				manager, _ := Create(&IFaceMock{
					SetFilterFunc: func(device.PacketFilter) error { return nil },
				}, false, flowLogger, iface.DefaultMTU)
				defer b.Cleanup(func() {
					require.NoError(b, manager.Close(nil))
				})

				// Apply scenario-specific setup
				sc.setupFunc(manager)

				// Generate test packets
				srcIP := generateRandomIPs(1)[0]
				dstIP := generateRandomIPs(1)[0]
				srcPort := uint16(1024 + b.N%60000)
				dstPort := uint16(80)

				outbound := generatePacket(b, srcIP, dstIP, srcPort, dstPort, proto.proto)
				inbound := generatePacket(b, dstIP, srcIP, dstPort, srcPort, proto.proto)

				// For stateful scenarios, establish the connection
				if sc.stateful {
					manager.filterOutbound(outbound, 0)
				}

				// Measure inbound packet processing
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					manager.filterInbound(inbound, 0)
				}
			})
		}
	}
}

// BenchmarkStateScaling measures how performance scales with connection table size
func BenchmarkStateScaling(b *testing.B) {
	connCounts := []int{100, 1000, 10000, 100000}

	for _, count := range connCounts {
		b.Run(fmt.Sprintf("conns_%d", count), func(b *testing.B) {
			manager, _ := Create(&IFaceMock{
				SetFilterFunc: func(device.PacketFilter) error { return nil },
			}, false, flowLogger, iface.DefaultMTU)
			b.Cleanup(func() {
				require.NoError(b, manager.Close(nil))
			})

			// Pre-populate connection table
			srcIPs := generateRandomIPs(count)
			dstIPs := generateRandomIPs(count)
			for i := 0; i < count; i++ {
				outbound := generatePacket(b, srcIPs[i], dstIPs[i],
					uint16(1024+i), 80, layers.IPProtocolTCP)
				manager.filterOutbound(outbound, 0)
			}

			// Test packet
			testOut := generatePacket(b, srcIPs[0], dstIPs[0], 1024, 80, layers.IPProtocolTCP)
			testIn := generatePacket(b, dstIPs[0], srcIPs[0], 80, 1024, layers.IPProtocolTCP)

			// First establish our test connection
			manager.filterOutbound(testOut, 0)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				manager.filterInbound(testIn, 0)
			}
		})
	}
}

// BenchmarkEstablishmentOverhead measures the overhead of connection establishment
func BenchmarkEstablishmentOverhead(b *testing.B) {
	scenarios := []struct {
		name        string
		established bool
	}{
		{"established", true},
		{"new", false},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			manager, _ := Create(&IFaceMock{
				SetFilterFunc: func(device.PacketFilter) error { return nil },
			}, false, flowLogger, iface.DefaultMTU)
			b.Cleanup(func() {
				require.NoError(b, manager.Close(nil))
			})

			srcIP := generateRandomIPs(1)[0]
			dstIP := generateRandomIPs(1)[0]
			outbound := generatePacket(b, srcIP, dstIP, 1024, 80, layers.IPProtocolTCP)
			inbound := generatePacket(b, dstIP, srcIP, 80, 1024, layers.IPProtocolTCP)

			if sc.established {
				manager.filterOutbound(outbound, 0)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				manager.filterInbound(inbound, 0)
			}
		})
	}
}

// BenchmarkRoutedNetworkReturn compares approaches for handling routed network return traffic
func BenchmarkRoutedNetworkReturn(b *testing.B) {
	scenarios := []struct {
		name       string
		proto      layers.IPProtocol
		state      string // "new", "established", "post_handshake" (TCP only)
		setupFunc  func(*Manager)
		genPackets func(net.IP, net.IP) ([]byte, []byte) // generates appropriate packets for the scenario
		desc       string
	}{
		{
			name:  "allow_non_wg_tcp_new",
			proto: layers.IPProtocolTCP,
			state: "new",
			setupFunc: func(m *Manager) {
				b.Setenv("NB_DISABLE_CONNTRACK", "1")
			},
			genPackets: func(srcIP, dstIP net.IP) ([]byte, []byte) {
				return generatePacket(b, srcIP, dstIP, 1024, 80, layers.IPProtocolTCP),
					generatePacket(b, dstIP, srcIP, 80, 1024, layers.IPProtocolTCP)
			},
			desc: "Allow non-WG: TCP new connection",
		},
		{
			name:  "allow_non_wg_tcp_established",
			proto: layers.IPProtocolTCP,
			state: "established",
			setupFunc: func(m *Manager) {
				b.Setenv("NB_DISABLE_CONNTRACK", "1")
			},
			genPackets: func(srcIP, dstIP net.IP) ([]byte, []byte) {
				// Generate packets with ACK flag for established connection
				return generateTCPPacketWithFlags(b, srcIP, dstIP, 1024, 80, uint16(conntrack.TCPAck)),
					generateTCPPacketWithFlags(b, dstIP, srcIP, 80, 1024, uint16(conntrack.TCPAck))
			},
			desc: "Allow non-WG: TCP established connection",
		},
		{
			name:  "allow_non_wg_udp_new",
			proto: layers.IPProtocolUDP,
			state: "new",
			setupFunc: func(m *Manager) {
				b.Setenv("NB_DISABLE_CONNTRACK", "1")
			},
			genPackets: func(srcIP, dstIP net.IP) ([]byte, []byte) {
				return generatePacket(b, srcIP, dstIP, 1024, 80, layers.IPProtocolUDP),
					generatePacket(b, dstIP, srcIP, 80, 1024, layers.IPProtocolUDP)
			},
			desc: "Allow non-WG: UDP new connection",
		},
		{
			name:  "allow_non_wg_udp_established",
			proto: layers.IPProtocolUDP,
			state: "established",
			setupFunc: func(m *Manager) {
				b.Setenv("NB_DISABLE_CONNTRACK", "1")
			},
			genPackets: func(srcIP, dstIP net.IP) ([]byte, []byte) {
				return generatePacket(b, srcIP, dstIP, 1024, 80, layers.IPProtocolUDP),
					generatePacket(b, dstIP, srcIP, 80, 1024, layers.IPProtocolUDP)
			},
			desc: "Allow non-WG: UDP established connection",
		},
		{
			name:  "stateful_tcp_new",
			proto: layers.IPProtocolTCP,
			state: "new",
			setupFunc: func(m *Manager) {
				require.NoError(b, os.Unsetenv("NB_DISABLE_CONNTRACK"))
			},
			genPackets: func(srcIP, dstIP net.IP) ([]byte, []byte) {
				return generatePacket(b, srcIP, dstIP, 1024, 80, layers.IPProtocolTCP),
					generatePacket(b, dstIP, srcIP, 80, 1024, layers.IPProtocolTCP)
			},
			desc: "Stateful: TCP new connection",
		},
		{
			name:  "stateful_tcp_established",
			proto: layers.IPProtocolTCP,
			state: "established",
			setupFunc: func(m *Manager) {
				require.NoError(b, os.Unsetenv("NB_DISABLE_CONNTRACK"))
			},
			genPackets: func(srcIP, dstIP net.IP) ([]byte, []byte) {
				// Generate established TCP packets (ACK flag)
				return generateTCPPacketWithFlags(b, srcIP, dstIP, 1024, 80, uint16(conntrack.TCPAck)),
					generateTCPPacketWithFlags(b, dstIP, srcIP, 80, 1024, uint16(conntrack.TCPAck))
			},
			desc: "Stateful: TCP established connection",
		},
		{
			name:  "stateful_tcp_post_handshake",
			proto: layers.IPProtocolTCP,
			state: "post_handshake",
			setupFunc: func(m *Manager) {
				require.NoError(b, os.Unsetenv("NB_DISABLE_CONNTRACK"))
			},
			genPackets: func(srcIP, dstIP net.IP) ([]byte, []byte) {
				// Generate packets with PSH+ACK flags for data transfer
				return generateTCPPacketWithFlags(b, srcIP, dstIP, 1024, 80, uint16(conntrack.TCPPush|conntrack.TCPAck)),
					generateTCPPacketWithFlags(b, dstIP, srcIP, 80, 1024, uint16(conntrack.TCPPush|conntrack.TCPAck))
			},
			desc: "Stateful: TCP post-handshake data transfer",
		},
		{
			name:  "stateful_udp_new",
			proto: layers.IPProtocolUDP,
			state: "new",
			setupFunc: func(m *Manager) {
				require.NoError(b, os.Unsetenv("NB_DISABLE_CONNTRACK"))
			},
			genPackets: func(srcIP, dstIP net.IP) ([]byte, []byte) {
				return generatePacket(b, srcIP, dstIP, 1024, 80, layers.IPProtocolUDP),
					generatePacket(b, dstIP, srcIP, 80, 1024, layers.IPProtocolUDP)
			},
			desc: "Stateful: UDP new connection",
		},
		{
			name:  "stateful_udp_established",
			proto: layers.IPProtocolUDP,
			state: "established",
			setupFunc: func(m *Manager) {
				require.NoError(b, os.Unsetenv("NB_DISABLE_CONNTRACK"))
			},
			genPackets: func(srcIP, dstIP net.IP) ([]byte, []byte) {
				return generatePacket(b, srcIP, dstIP, 1024, 80, layers.IPProtocolUDP),
					generatePacket(b, dstIP, srcIP, 80, 1024, layers.IPProtocolUDP)
			},
			desc: "Stateful: UDP established connection",
		},
	}

	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			manager, _ := Create(&IFaceMock{
				SetFilterFunc: func(device.PacketFilter) error { return nil },
			}, false, flowLogger, iface.DefaultMTU)
			b.Cleanup(func() {
				require.NoError(b, manager.Close(nil))
			})

			// Setup scenario
			sc.setupFunc(manager)

			// Use IPs outside WG range for routed network simulation
			srcIP := net.ParseIP("192.168.1.2")
			dstIP := net.ParseIP("8.8.8.8")
			outbound, inbound := sc.genPackets(srcIP, dstIP)

			// For stateful cases and established connections
			if !strings.Contains(sc.name, "allow_non_wg") ||
				(strings.Contains(sc.state, "established") || sc.state == "post_handshake") {
				manager.filterOutbound(outbound, 0)

				// For TCP post-handshake, simulate full handshake
				if sc.state == "post_handshake" {
					// SYN
					syn := generateTCPPacketWithFlags(b, srcIP, dstIP, 1024, 80, uint16(conntrack.TCPSyn))
					manager.filterOutbound(syn, 0)
					// SYN-ACK
					synack := generateTCPPacketWithFlags(b, dstIP, srcIP, 80, 1024, uint16(conntrack.TCPSyn|conntrack.TCPAck))
					manager.filterInbound(synack, 0)
					// ACK
					ack := generateTCPPacketWithFlags(b, srcIP, dstIP, 1024, 80, uint16(conntrack.TCPAck))
					manager.filterOutbound(ack, 0)
				}
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				manager.filterInbound(inbound, 0)
			}
		})
	}
}

var scenarios = []struct {
	name      string
	stateful  bool // Whether conntrack is enabled
	rules     bool // Whether to add return traffic rules
	routed    bool // Whether to test routed network traffic
	connCount int  // Number of concurrent connections
	desc      string
}{
	{
		name:      "stateless_with_rules_100conns",
		stateful:  false,
		rules:     true,
		routed:    false,
		connCount: 100,
		desc:      "Pure stateless with return traffic rules, 100 conns",
	},
	{
		name:      "stateless_with_rules_1000conns",
		stateful:  false,
		rules:     true,
		routed:    false,
		connCount: 1000,
		desc:      "Pure stateless with return traffic rules, 1000 conns",
	},
	{
		name:      "stateful_no_rules_100conns",
		stateful:  true,
		rules:     false,
		routed:    false,
		connCount: 100,
		desc:      "Pure stateful tracking without rules, 100 conns",
	},
	{
		name:      "stateful_no_rules_1000conns",
		stateful:  true,
		rules:     false,
		routed:    false,
		connCount: 1000,
		desc:      "Pure stateful tracking without rules, 1000 conns",
	},
	{
		name:      "stateful_with_rules_100conns",
		stateful:  true,
		rules:     true,
		routed:    false,
		connCount: 100,
		desc:      "Combined stateful + rules (current implementation), 100 conns",
	},
	{
		name:      "stateful_with_rules_1000conns",
		stateful:  true,
		rules:     true,
		routed:    false,
		connCount: 1000,
		desc:      "Combined stateful + rules (current implementation), 1000 conns",
	},
	{
		name:      "routed_network_100conns",
		stateful:  true,
		rules:     false,
		routed:    true,
		connCount: 100,
		desc:      "Routed network traffic (non-WG), 100 conns",
	},
	{
		name:      "routed_network_1000conns",
		stateful:  true,
		rules:     false,
		routed:    true,
		connCount: 1000,
		desc:      "Routed network traffic (non-WG), 1000 conns",
	},
}

// BenchmarkLongLivedConnections tests performance with realistic TCP traffic patterns
func BenchmarkLongLivedConnections(b *testing.B) {
	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			// Configure stateful/stateless mode
			if !sc.stateful {
				b.Setenv("NB_DISABLE_CONNTRACK", "1")
			} else {
				require.NoError(b, os.Unsetenv("NB_DISABLE_CONNTRACK"))
			}

			manager, _ := Create(&IFaceMock{
				SetFilterFunc: func(device.PacketFilter) error { return nil },
			}, false, flowLogger, iface.DefaultMTU)
			defer b.Cleanup(func() {
				require.NoError(b, manager.Close(nil))
			})

			// Setup initial state based on scenario
			if sc.rules {
				// Single rule to allow all return traffic from port 80
				_, err := manager.AddPeerFiltering(nil, net.ParseIP("0.0.0.0"), fw.ProtocolTCP, &fw.Port{Values: []uint16{80}}, nil, fw.ActionAccept, "")
				require.NoError(b, err)
			}

			// Generate IPs for connections
			srcIPs := make([]net.IP, sc.connCount)
			dstIPs := make([]net.IP, sc.connCount)

			for i := 0; i < sc.connCount; i++ {
				if sc.routed {
					srcIPs[i] = net.IPv4(192, 168, 1, byte(2+(i%250))).To4()
					dstIPs[i] = net.IPv4(8, 8, byte((i/250)%255), byte(2+(i%250))).To4()
				} else {
					srcIPs[i] = generateRandomIPs(1)[0]
					dstIPs[i] = generateRandomIPs(1)[0]
				}
			}

			// Create established connections
			for i := 0; i < sc.connCount; i++ {
				// Initial SYN
				syn := generateTCPPacketWithFlags(b, srcIPs[i], dstIPs[i],
					uint16(1024+i), 80, uint16(conntrack.TCPSyn))
				manager.filterOutbound(syn, 0)

				// SYN-ACK
				synack := generateTCPPacketWithFlags(b, dstIPs[i], srcIPs[i],
					80, uint16(1024+i), uint16(conntrack.TCPSyn|conntrack.TCPAck))
				manager.filterInbound(synack, 0)

				// ACK
				ack := generateTCPPacketWithFlags(b, srcIPs[i], dstIPs[i],
					uint16(1024+i), 80, uint16(conntrack.TCPAck))
				manager.filterOutbound(ack, 0)
			}

			// Prepare test packets simulating bidirectional traffic
			inPackets := make([][]byte, sc.connCount)
			outPackets := make([][]byte, sc.connCount)
			for i := 0; i < sc.connCount; i++ {
				// Server -> Client (inbound)
				inPackets[i] = generateTCPPacketWithFlags(b, dstIPs[i], srcIPs[i],
					80, uint16(1024+i), uint16(conntrack.TCPPush|conntrack.TCPAck))
				// Client -> Server (outbound)
				outPackets[i] = generateTCPPacketWithFlags(b, srcIPs[i], dstIPs[i],
					uint16(1024+i), 80, uint16(conntrack.TCPPush|conntrack.TCPAck))
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				connIdx := i % sc.connCount

				// Simulate bidirectional traffic
				// First outbound data
				manager.filterOutbound(outPackets[connIdx], 0)
				// Then inbound response - this is what we're actually measuring
				manager.filterInbound(inPackets[connIdx], 0)
			}
		})
	}
}

// BenchmarkShortLivedConnections tests performance with many short-lived connections
func BenchmarkShortLivedConnections(b *testing.B) {
	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			// Configure stateful/stateless mode
			if !sc.stateful {
				b.Setenv("NB_DISABLE_CONNTRACK", "1")
			} else {
				require.NoError(b, os.Unsetenv("NB_DISABLE_CONNTRACK"))
			}

			manager, _ := Create(&IFaceMock{
				SetFilterFunc: func(device.PacketFilter) error { return nil },
			}, false, flowLogger, iface.DefaultMTU)
			defer b.Cleanup(func() {
				require.NoError(b, manager.Close(nil))
			})

			// Setup initial state based on scenario
			if sc.rules {
				// Single rule to allow all return traffic from port 80
				_, err := manager.AddPeerFiltering(nil, net.ParseIP("0.0.0.0"), fw.ProtocolTCP, &fw.Port{Values: []uint16{80}}, nil, fw.ActionAccept, "")
				require.NoError(b, err)
			}

			// Generate IPs for connections
			srcIPs := make([]net.IP, sc.connCount)
			dstIPs := make([]net.IP, sc.connCount)

			for i := 0; i < sc.connCount; i++ {
				if sc.routed {
					srcIPs[i] = net.IPv4(192, 168, 1, byte(2+(i%250))).To4()
					dstIPs[i] = net.IPv4(8, 8, byte((i/250)%255), byte(2+(i%250))).To4()
				} else {
					srcIPs[i] = generateRandomIPs(1)[0]
					dstIPs[i] = generateRandomIPs(1)[0]
				}
			}

			// Create packet patterns for a complete HTTP-like short connection:
			// 1. Initial handshake (SYN, SYN-ACK, ACK)
			// 2. HTTP Request (PSH+ACK from client)
			// 3. HTTP Response (PSH+ACK from server)
			// 4. Connection teardown (FIN+ACK, ACK, FIN+ACK, ACK)
			type connPackets struct {
				syn       []byte
				synAck    []byte
				ack       []byte
				request   []byte
				response  []byte
				finClient []byte
				ackServer []byte
				finServer []byte
				ackClient []byte
			}

			// Generate all possible connection patterns
			patterns := make([]connPackets, sc.connCount)
			for i := 0; i < sc.connCount; i++ {
				patterns[i] = connPackets{
					// Handshake
					syn: generateTCPPacketWithFlags(b, srcIPs[i], dstIPs[i],
						uint16(1024+i), 80, uint16(conntrack.TCPSyn)),
					synAck: generateTCPPacketWithFlags(b, dstIPs[i], srcIPs[i],
						80, uint16(1024+i), uint16(conntrack.TCPSyn|conntrack.TCPAck)),
					ack: generateTCPPacketWithFlags(b, srcIPs[i], dstIPs[i],
						uint16(1024+i), 80, uint16(conntrack.TCPAck)),

					// Data transfer
					request: generateTCPPacketWithFlags(b, srcIPs[i], dstIPs[i],
						uint16(1024+i), 80, uint16(conntrack.TCPPush|conntrack.TCPAck)),
					response: generateTCPPacketWithFlags(b, dstIPs[i], srcIPs[i],
						80, uint16(1024+i), uint16(conntrack.TCPPush|conntrack.TCPAck)),

					// Connection teardown
					finClient: generateTCPPacketWithFlags(b, srcIPs[i], dstIPs[i],
						uint16(1024+i), 80, uint16(conntrack.TCPFin|conntrack.TCPAck)),
					ackServer: generateTCPPacketWithFlags(b, dstIPs[i], srcIPs[i],
						80, uint16(1024+i), uint16(conntrack.TCPAck)),
					finServer: generateTCPPacketWithFlags(b, dstIPs[i], srcIPs[i],
						80, uint16(1024+i), uint16(conntrack.TCPFin|conntrack.TCPAck)),
					ackClient: generateTCPPacketWithFlags(b, srcIPs[i], dstIPs[i],
						uint16(1024+i), 80, uint16(conntrack.TCPAck)),
				}
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				// Each iteration creates a new short-lived connection
				connIdx := i % sc.connCount
				p := patterns[connIdx]

				// Connection establishment
				manager.filterOutbound(p.syn, 0)
				manager.filterInbound(p.synAck, 0)
				manager.filterOutbound(p.ack, 0)

				// Data transfer
				manager.filterOutbound(p.request, 0)
				manager.filterInbound(p.response, 0)

				// Connection teardown
				manager.filterOutbound(p.finClient, 0)
				manager.filterInbound(p.ackServer, 0)
				manager.filterInbound(p.finServer, 0)
				manager.filterOutbound(p.ackClient, 0)
			}
		})
	}
}

// BenchmarkParallelLongLivedConnections tests performance with realistic TCP traffic patterns in parallel
func BenchmarkParallelLongLivedConnections(b *testing.B) {
	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			// Configure stateful/stateless mode
			if !sc.stateful {
				b.Setenv("NB_DISABLE_CONNTRACK", "1")
			} else {
				require.NoError(b, os.Unsetenv("NB_DISABLE_CONNTRACK"))
			}

			manager, _ := Create(&IFaceMock{
				SetFilterFunc: func(device.PacketFilter) error { return nil },
			}, false, flowLogger, iface.DefaultMTU)
			defer b.Cleanup(func() {
				require.NoError(b, manager.Close(nil))
			})

			// Setup initial state based on scenario
			if sc.rules {
				_, err := manager.AddPeerFiltering(nil, net.ParseIP("0.0.0.0"), fw.ProtocolTCP, &fw.Port{Values: []uint16{80}}, nil, fw.ActionAccept, "")
				require.NoError(b, err)
			}

			// Generate IPs for connections
			srcIPs := make([]net.IP, sc.connCount)
			dstIPs := make([]net.IP, sc.connCount)

			for i := 0; i < sc.connCount; i++ {
				if sc.routed {
					srcIPs[i] = net.IPv4(192, 168, 1, byte(2+(i%250))).To4()
					dstIPs[i] = net.IPv4(8, 8, byte((i/250)%255), byte(2+(i%250))).To4()
				} else {
					srcIPs[i] = generateRandomIPs(1)[0]
					dstIPs[i] = generateRandomIPs(1)[0]
				}
			}

			// Create established connections
			for i := 0; i < sc.connCount; i++ {
				syn := generateTCPPacketWithFlags(b, srcIPs[i], dstIPs[i],
					uint16(1024+i), 80, uint16(conntrack.TCPSyn))
				manager.filterOutbound(syn, 0)

				synack := generateTCPPacketWithFlags(b, dstIPs[i], srcIPs[i],
					80, uint16(1024+i), uint16(conntrack.TCPSyn|conntrack.TCPAck))
				manager.filterInbound(synack, 0)

				ack := generateTCPPacketWithFlags(b, srcIPs[i], dstIPs[i],
					uint16(1024+i), 80, uint16(conntrack.TCPAck))
				manager.filterOutbound(ack, 0)
			}

			// Pre-generate test packets
			inPackets := make([][]byte, sc.connCount)
			outPackets := make([][]byte, sc.connCount)
			for i := 0; i < sc.connCount; i++ {
				inPackets[i] = generateTCPPacketWithFlags(b, dstIPs[i], srcIPs[i],
					80, uint16(1024+i), uint16(conntrack.TCPPush|conntrack.TCPAck))
				outPackets[i] = generateTCPPacketWithFlags(b, srcIPs[i], dstIPs[i],
					uint16(1024+i), 80, uint16(conntrack.TCPPush|conntrack.TCPAck))
			}

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				// Each goroutine gets its own counter to distribute load
				counter := 0
				for pb.Next() {
					connIdx := counter % sc.connCount
					counter++

					// Simulate bidirectional traffic
					manager.filterOutbound(outPackets[connIdx], 0)
					manager.filterInbound(inPackets[connIdx], 0)
				}
			})
		})
	}
}

// BenchmarkParallelShortLivedConnections tests performance with many short-lived connections in parallel
func BenchmarkParallelShortLivedConnections(b *testing.B) {
	for _, sc := range scenarios {
		b.Run(sc.name, func(b *testing.B) {
			// Configure stateful/stateless mode
			if !sc.stateful {
				b.Setenv("NB_DISABLE_CONNTRACK", "1")
			} else {
				require.NoError(b, os.Unsetenv("NB_DISABLE_CONNTRACK"))
			}

			manager, _ := Create(&IFaceMock{
				SetFilterFunc: func(device.PacketFilter) error { return nil },
			}, false, flowLogger, iface.DefaultMTU)
			defer b.Cleanup(func() {
				require.NoError(b, manager.Close(nil))
			})

			if sc.rules {
				_, err := manager.AddPeerFiltering(nil, net.ParseIP("0.0.0.0"), fw.ProtocolTCP, &fw.Port{Values: []uint16{80}}, nil, fw.ActionAccept, "")
				require.NoError(b, err)
			}

			// Generate IPs and pre-generate all packet patterns
			srcIPs := make([]net.IP, sc.connCount)
			dstIPs := make([]net.IP, sc.connCount)
			for i := 0; i < sc.connCount; i++ {
				if sc.routed {
					srcIPs[i] = net.IPv4(192, 168, 1, byte(2+(i%250))).To4()
					dstIPs[i] = net.IPv4(8, 8, byte((i/250)%255), byte(2+(i%250))).To4()
				} else {
					srcIPs[i] = generateRandomIPs(1)[0]
					dstIPs[i] = generateRandomIPs(1)[0]
				}
			}

			type connPackets struct {
				syn       []byte
				synAck    []byte
				ack       []byte
				request   []byte
				response  []byte
				finClient []byte
				ackServer []byte
				finServer []byte
				ackClient []byte
			}

			patterns := make([]connPackets, sc.connCount)
			for i := 0; i < sc.connCount; i++ {
				patterns[i] = connPackets{
					syn: generateTCPPacketWithFlags(b, srcIPs[i], dstIPs[i],
						uint16(1024+i), 80, uint16(conntrack.TCPSyn)),
					synAck: generateTCPPacketWithFlags(b, dstIPs[i], srcIPs[i],
						80, uint16(1024+i), uint16(conntrack.TCPSyn|conntrack.TCPAck)),
					ack: generateTCPPacketWithFlags(b, srcIPs[i], dstIPs[i],
						uint16(1024+i), 80, uint16(conntrack.TCPAck)),
					request: generateTCPPacketWithFlags(b, srcIPs[i], dstIPs[i],
						uint16(1024+i), 80, uint16(conntrack.TCPPush|conntrack.TCPAck)),
					response: generateTCPPacketWithFlags(b, dstIPs[i], srcIPs[i],
						80, uint16(1024+i), uint16(conntrack.TCPPush|conntrack.TCPAck)),
					finClient: generateTCPPacketWithFlags(b, srcIPs[i], dstIPs[i],
						uint16(1024+i), 80, uint16(conntrack.TCPFin|conntrack.TCPAck)),
					ackServer: generateTCPPacketWithFlags(b, dstIPs[i], srcIPs[i],
						80, uint16(1024+i), uint16(conntrack.TCPAck)),
					finServer: generateTCPPacketWithFlags(b, dstIPs[i], srcIPs[i],
						80, uint16(1024+i), uint16(conntrack.TCPFin|conntrack.TCPAck)),
					ackClient: generateTCPPacketWithFlags(b, srcIPs[i], dstIPs[i],
						uint16(1024+i), 80, uint16(conntrack.TCPAck)),
				}
			}

			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				counter := 0
				for pb.Next() {
					connIdx := counter % sc.connCount
					counter++
					p := patterns[connIdx]

					// Full connection lifecycle
					manager.filterOutbound(p.syn, 0)
					manager.filterInbound(p.synAck, 0)
					manager.filterOutbound(p.ack, 0)

					manager.filterOutbound(p.request, 0)
					manager.filterInbound(p.response, 0)

					manager.filterOutbound(p.finClient, 0)
					manager.filterInbound(p.ackServer, 0)
					manager.filterInbound(p.finServer, 0)
					manager.filterOutbound(p.ackClient, 0)
				}
			})
		})
	}
}

func BenchmarkRouteACLs(b *testing.B) {
	manager := setupRoutedManager(b, "10.10.0.100/16")

	// Add several route rules to simulate real-world scenario
	rules := []struct {
		sources []netip.Prefix
		dest    netip.Prefix
		proto   fw.Protocol
		port    *fw.Port
	}{
		{
			sources: []netip.Prefix{netip.MustParsePrefix("100.10.0.0/16")},
			dest:    netip.MustParsePrefix("192.168.1.0/24"),
			proto:   fw.ProtocolTCP,
			port:    &fw.Port{Values: []uint16{80, 443}},
		},
		{
			sources: []netip.Prefix{
				netip.MustParsePrefix("172.16.0.0/12"),
				netip.MustParsePrefix("10.0.0.0/8"),
			},
			dest:  netip.MustParsePrefix("0.0.0.0/0"),
			proto: fw.ProtocolICMP,
		},
		{
			sources: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			dest:    netip.MustParsePrefix("192.168.0.0/16"),
			proto:   fw.ProtocolUDP,
			port:    &fw.Port{Values: []uint16{53}},
		},
	}

	for _, r := range rules {
		dst := fw.Network{Prefix: r.dest}
		_, err := manager.AddRouteFiltering(nil, r.sources, dst, r.proto, nil, r.port, fw.ActionAccept)
		if err != nil {
			b.Fatal(err)
		}
	}

	// Test cases that exercise different matching scenarios
	cases := []struct {
		srcIP   string
		dstIP   string
		proto   fw.Protocol
		dstPort uint16
	}{
		{"100.10.0.1", "192.168.1.100", fw.ProtocolTCP, 443}, // Match first rule
		{"172.16.0.1", "8.8.8.8", fw.ProtocolICMP, 0},        // Match second rule
		{"1.1.1.1", "192.168.1.53", fw.ProtocolUDP, 53},      // Match third rule
		{"192.168.1.1", "10.0.0.1", fw.ProtocolTCP, 8080},    // No match
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, tc := range cases {
			srcIP := netip.MustParseAddr(tc.srcIP)
			dstIP := netip.MustParseAddr(tc.dstIP)
			manager.routeACLsPass(srcIP, dstIP, protoToLayer(tc.proto, layers.LayerTypeIPv4), 0, tc.dstPort)
		}
	}
}

// BenchmarkMSSClamping benchmarks the MSS clamping impact on filterOutbound.
// This shows the overhead difference between the common case (non-SYN packets, fast path)
// and the rare case (SYN packets that need clamping, expensive path).
func BenchmarkMSSClamping(b *testing.B) {
	scenarios := []struct {
		name        string
		description string
		genPacket   func(*testing.B, net.IP, net.IP) []byte
		frequency   string
	}{
		{
			name:        "syn_needs_clamp",
			description: "SYN packet needing MSS clamping",
			genPacket: func(b *testing.B, src, dst net.IP) []byte {
				return generateSYNPacketWithMSS(b, src, dst, 12345, 80, 1460)
			},
			frequency: "~0.1% of traffic - EXPENSIVE",
		},
		{
			name:        "syn_no_clamp_needed",
			description: "SYN packet with already-small MSS",
			genPacket: func(b *testing.B, src, dst net.IP) []byte {
				return generateSYNPacketWithMSS(b, src, dst, 12345, 80, 1200)
			},
			frequency: "~0.05% of traffic",
		},
		{
			name:        "tcp_ack",
			description: "Non-SYN TCP packet (ACK, data transfer)",
			genPacket: func(b *testing.B, src, dst net.IP) []byte {
				return generateTCPPacketWithFlags(b, src, dst, 12345, 80, uint16(conntrack.TCPAck))
			},
			frequency: "~60-70% of traffic - FAST PATH",
		},
		{
			name:        "tcp_psh_ack",
			description: "TCP data packet (PSH+ACK)",
			genPacket: func(b *testing.B, src, dst net.IP) []byte {
				return generateTCPPacketWithFlags(b, src, dst, 12345, 80, uint16(conntrack.TCPPush|conntrack.TCPAck))
			},
			frequency: "~10-20% of traffic - FAST PATH",
		},
		{
			name:        "udp",
			description: "UDP packet",
			genPacket: func(b *testing.B, src, dst net.IP) []byte {
				return generatePacket(b, src, dst, 12345, 80, layers.IPProtocolUDP)
			},
			frequency: "~20-30% of traffic - FAST PATH",
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

			manager.mssClampEnabled = true
			manager.mssClampValue = 1240

			srcIP := net.ParseIP("100.64.0.2")
			dstIP := net.ParseIP("8.8.8.8")
			packet := sc.genPacket(b, srcIP, dstIP)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				manager.filterOutbound(packet, len(packet))
			}
		})
	}
}

// BenchmarkMSSClampingOverhead compares overhead of MSS clamping enabled vs disabled
// for the common case (non-SYN TCP packets).
func BenchmarkMSSClampingOverhead(b *testing.B) {
	scenarios := []struct {
		name      string
		enabled   bool
		genPacket func(*testing.B, net.IP, net.IP) []byte
	}{
		{
			name:    "disabled_tcp_ack",
			enabled: false,
			genPacket: func(b *testing.B, src, dst net.IP) []byte {
				return generateTCPPacketWithFlags(b, src, dst, 12345, 80, uint16(conntrack.TCPAck))
			},
		},
		{
			name:    "enabled_tcp_ack",
			enabled: true,
			genPacket: func(b *testing.B, src, dst net.IP) []byte {
				return generateTCPPacketWithFlags(b, src, dst, 12345, 80, uint16(conntrack.TCPAck))
			},
		},
		{
			name:    "disabled_syn_needs_clamp",
			enabled: false,
			genPacket: func(b *testing.B, src, dst net.IP) []byte {
				return generateSYNPacketWithMSS(b, src, dst, 12345, 80, 1460)
			},
		},
		{
			name:    "enabled_syn_needs_clamp",
			enabled: true,
			genPacket: func(b *testing.B, src, dst net.IP) []byte {
				return generateSYNPacketWithMSS(b, src, dst, 12345, 80, 1460)
			},
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

			manager.mssClampEnabled = sc.enabled
			if sc.enabled {
				manager.mssClampValue = 1240
			}

			srcIP := net.ParseIP("100.64.0.2")
			dstIP := net.ParseIP("8.8.8.8")
			packet := sc.genPacket(b, srcIP, dstIP)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				manager.filterOutbound(packet, len(packet))
			}
		})
	}
}

// BenchmarkMSSClampingMemory measures memory allocations for common vs rare cases
func BenchmarkMSSClampingMemory(b *testing.B) {
	scenarios := []struct {
		name      string
		genPacket func(*testing.B, net.IP, net.IP) []byte
	}{
		{
			name: "tcp_ack_fast_path",
			genPacket: func(b *testing.B, src, dst net.IP) []byte {
				return generateTCPPacketWithFlags(b, src, dst, 12345, 80, uint16(conntrack.TCPAck))
			},
		},
		{
			name: "syn_needs_clamp",
			genPacket: func(b *testing.B, src, dst net.IP) []byte {
				return generateSYNPacketWithMSS(b, src, dst, 12345, 80, 1460)
			},
		},
		{
			name: "udp_fast_path",
			genPacket: func(b *testing.B, src, dst net.IP) []byte {
				return generatePacket(b, src, dst, 12345, 80, layers.IPProtocolUDP)
			},
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

			manager.mssClampEnabled = true
			manager.mssClampValue = 1240

			srcIP := net.ParseIP("100.64.0.2")
			dstIP := net.ParseIP("8.8.8.8")
			packet := sc.genPacket(b, srcIP, dstIP)

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				manager.filterOutbound(packet, len(packet))
			}
		})
	}
}

func generateSYNPacketNoMSS(b *testing.B, srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	b.Helper()

	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    srcIP,
		DstIP:    dstIP,
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     true,
		Seq:     1000,
		Window:  65535,
	}

	require.NoError(b, tcp.SetNetworkLayerForChecksum(ip))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	require.NoError(b, gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload([]byte{})))
	return buf.Bytes()
}
