package uspfilter

import (
	"fmt"
	"math/rand"
	"net"
	"os"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
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

func generatePacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, protocol layers.IPProtocol) []byte {
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
		tcp.SetNetworkLayerForChecksum(ipv4)
		transportLayer = tcp
	case layers.IPProtocolUDP:
		udp := &layers.UDP{
			SrcPort: layers.UDPPort(srcPort),
			DstPort: layers.UDPPort(dstPort),
		}
		udp.SetNetworkLayerForChecksum(ipv4)
		transportLayer = udp
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	gopacket.SerializeLayers(buf, opts, ipv4, transportLayer, gopacket.Payload([]byte("test")))
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
				m.AddPeerFiltering(net.ParseIP("0.0.0.0"), fw.ProtocolALL, nil, nil,
					fw.RuleDirectionIN, fw.ActionAccept, "", "allow all")
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
					m.AddPeerFiltering(ip, fw.ProtocolTCP,
						&fw.Port{Values: []int{1024 + i}},
						&fw.Port{Values: []int{80}},
						fw.RuleDirectionIN, fw.ActionAccept, "", "explicit return")
				}
			},
			desc: "Explicit rules matching return traffic patterns without state",
		},
		{
			name:     "stateful_with_established",
			stateful: true,
			setupFunc: func(m *Manager) {
				// Add some basic rules but rely on state for established connections
				m.AddPeerFiltering(net.ParseIP("0.0.0.0"), fw.ProtocolTCP, nil, nil,
					fw.RuleDirectionIN, fw.ActionDrop, "", "default drop")
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
					os.Setenv("NB_DISABLE_CONNTRACK", "1")
				} else {
					os.Unsetenv("NB_DISABLE_CONNTRACK")
				}

				// Create manager and basic setup
				manager, _ := Create(&IFaceMock{
					SetFilterFunc: func(device.PacketFilter) error { return nil },
				})
				defer manager.Reset(nil)

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

				outbound := generatePacket(srcIP, dstIP, srcPort, dstPort, proto.proto)
				inbound := generatePacket(dstIP, srcIP, dstPort, srcPort, proto.proto)

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
			defer manager.Reset(nil)

			manager.wgNetwork = &net.IPNet{
				IP:   net.ParseIP("100.64.0.0"),
				Mask: net.CIDRMask(10, 32),
			}

			// Pre-populate connection table
			srcIPs := generateRandomIPs(count)
			dstIPs := generateRandomIPs(count)
			for i := 0; i < count; i++ {
				outbound := generatePacket(srcIPs[i], dstIPs[i],
					uint16(1024+i), 80, layers.IPProtocolTCP)
				manager.processOutgoingHooks(outbound)
			}

			// Test packet
			testOut := generatePacket(srcIPs[0], dstIPs[0], 1024, 80, layers.IPProtocolTCP)
			testIn := generatePacket(dstIPs[0], srcIPs[0], 80, 1024, layers.IPProtocolTCP)

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
			defer manager.Reset(nil)

			manager.wgNetwork = &net.IPNet{
				IP:   net.ParseIP("100.64.0.0"),
				Mask: net.CIDRMask(10, 32),
			}

			srcIP := generateRandomIPs(1)[0]
			dstIP := generateRandomIPs(1)[0]
			outbound := generatePacket(srcIP, dstIP, 1024, 80, layers.IPProtocolTCP)
			inbound := generatePacket(dstIP, srcIP, 80, 1024, layers.IPProtocolTCP)

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
