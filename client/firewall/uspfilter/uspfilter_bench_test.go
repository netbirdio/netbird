package uspfilter

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
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
				_, err := m.AddPeerFiltering(net.ParseIP("0.0.0.0"), fw.ProtocolALL, nil, nil,
					fw.RuleDirectionIN, fw.ActionAccept, "", "allow all")
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
					_, err := m.AddPeerFiltering(ip, fw.ProtocolTCP,
						&fw.Port{Values: []int{1024 + i}},
						&fw.Port{Values: []int{80}},
						fw.RuleDirectionIN, fw.ActionAccept, "", "explicit return")
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
				_, err := m.AddPeerFiltering(net.ParseIP("0.0.0.0"), fw.ProtocolTCP, nil, nil,
					fw.RuleDirectionIN, fw.ActionDrop, "", "default drop")
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
				})
				defer b.Cleanup(func() {
					require.NoError(b, manager.Reset(nil))
				})

				manager.wgNetwork = &net.IPNet{
					IP:   net.ParseIP("100.64.0.0"),
					Mask: net.CIDRMask(10, 32),
				}

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
					manager.processOutgoingHooks(outbound)
				}

				// Measure inbound packet processing
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					manager.dropFilter(inbound, manager.incomingRules)
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
			})
			b.Cleanup(func() {
				require.NoError(b, manager.Reset(nil))
			})

			manager.wgNetwork = &net.IPNet{
				IP:   net.ParseIP("100.64.0.0"),
				Mask: net.CIDRMask(10, 32),
			}

			// Pre-populate connection table
			srcIPs := generateRandomIPs(count)
			dstIPs := generateRandomIPs(count)
			for i := 0; i < count; i++ {
				outbound := generatePacket(b, srcIPs[i], dstIPs[i],
					uint16(1024+i), 80, layers.IPProtocolTCP)
				manager.processOutgoingHooks(outbound)
			}

			// Test packet
			testOut := generatePacket(b, srcIPs[0], dstIPs[0], 1024, 80, layers.IPProtocolTCP)
			testIn := generatePacket(b, dstIPs[0], srcIPs[0], 80, 1024, layers.IPProtocolTCP)

			// First establish our test connection
			manager.processOutgoingHooks(testOut)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				manager.dropFilter(testIn, manager.incomingRules)
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
			})
			b.Cleanup(func() {
				require.NoError(b, manager.Reset(nil))
			})

			manager.wgNetwork = &net.IPNet{
				IP:   net.ParseIP("100.64.0.0"),
				Mask: net.CIDRMask(10, 32),
			}

			srcIP := generateRandomIPs(1)[0]
			dstIP := generateRandomIPs(1)[0]
			outbound := generatePacket(b, srcIP, dstIP, 1024, 80, layers.IPProtocolTCP)
			inbound := generatePacket(b, dstIP, srcIP, 80, 1024, layers.IPProtocolTCP)

			if sc.established {
				manager.processOutgoingHooks(outbound)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				manager.dropFilter(inbound, manager.incomingRules)
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
				m.wgNetwork = &net.IPNet{
					IP:   net.ParseIP("100.64.0.0"),
					Mask: net.CIDRMask(10, 32),
				}
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
				m.wgNetwork = &net.IPNet{
					IP:   net.ParseIP("100.64.0.0"),
					Mask: net.CIDRMask(10, 32),
				}
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
				m.wgNetwork = &net.IPNet{
					IP:   net.ParseIP("100.64.0.0"),
					Mask: net.CIDRMask(10, 32),
				}
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
				m.wgNetwork = &net.IPNet{
					IP:   net.ParseIP("100.64.0.0"),
					Mask: net.CIDRMask(10, 32),
				}
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
				m.wgNetwork = &net.IPNet{
					IP:   net.ParseIP("0.0.0.0"),
					Mask: net.CIDRMask(0, 32),
				}
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
				m.wgNetwork = &net.IPNet{
					IP:   net.ParseIP("0.0.0.0"),
					Mask: net.CIDRMask(0, 32),
				}
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
				m.wgNetwork = &net.IPNet{
					IP:   net.ParseIP("0.0.0.0"),
					Mask: net.CIDRMask(0, 32),
				}
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
				m.wgNetwork = &net.IPNet{
					IP:   net.ParseIP("0.0.0.0"),
					Mask: net.CIDRMask(0, 32),
				}
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
				m.wgNetwork = &net.IPNet{
					IP:   net.ParseIP("0.0.0.0"),
					Mask: net.CIDRMask(0, 32),
				}
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
			})
			b.Cleanup(func() {
				require.NoError(b, manager.Reset(nil))
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
				manager.processOutgoingHooks(outbound)

				// For TCP post-handshake, simulate full handshake
				if sc.state == "post_handshake" {
					// SYN
					syn := generateTCPPacketWithFlags(b, srcIP, dstIP, 1024, 80, uint16(conntrack.TCPSyn))
					manager.processOutgoingHooks(syn)
					// SYN-ACK
					synack := generateTCPPacketWithFlags(b, dstIP, srcIP, 80, 1024, uint16(conntrack.TCPSyn|conntrack.TCPAck))
					manager.dropFilter(synack, manager.incomingRules)
					// ACK
					ack := generateTCPPacketWithFlags(b, srcIP, dstIP, 1024, 80, uint16(conntrack.TCPAck))
					manager.processOutgoingHooks(ack)
				}
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				manager.dropFilter(inbound, manager.incomingRules)
			}
		})
	}
}

// generateTCPPacketWithFlags creates a TCP packet with specific flags
func generateTCPPacketWithFlags(b *testing.B, srcIP, dstIP net.IP, srcPort, dstPort, flags uint16) []byte {
	b.Helper()

	ipv4 := &layers.IPv4{
		TTL:      64,
		Version:  4,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
	}

	// Set TCP flags
	tcp.SYN = (flags & uint16(conntrack.TCPSyn)) != 0
	tcp.ACK = (flags & uint16(conntrack.TCPAck)) != 0
	tcp.PSH = (flags & uint16(conntrack.TCPPush)) != 0
	tcp.RST = (flags & uint16(conntrack.TCPRst)) != 0
	tcp.FIN = (flags & uint16(conntrack.TCPFin)) != 0

	require.NoError(b, tcp.SetNetworkLayerForChecksum(ipv4))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	require.NoError(b, gopacket.SerializeLayers(buf, opts, ipv4, tcp, gopacket.Payload("test")))
	return buf.Bytes()
}
