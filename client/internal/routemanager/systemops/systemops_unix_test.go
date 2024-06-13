//go:build (linux && !android) || (darwin && !ios) || freebsd || openbsd || netbsd || dragonfly

package systemops

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbnet "github.com/netbirdio/netbird/util/net"
)

var expectedVPNint = "utun100"
var expectedExternalInt = "lo0"
var expectedInternalInt = "lo0"

type PacketExpectation struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort int
	DstPort int
	UDP     bool
	TCP     bool
}

type testCase struct {
	name              string
	destination       string
	expectedInterface string
	dialer            dialer
	expectedPacket    PacketExpectation
}

var testCases = []testCase{
	{
		name:              "To external host without custom dialer via vpn",
		destination:       "192.0.2.1:53",
		expectedInterface: expectedVPNint,
		dialer:            &net.Dialer{},
		expectedPacket:    createPacketExpectation("100.64.0.1", 12345, "192.0.2.1", 53),
	},
	{
		name:              "To external host with custom dialer via physical interface",
		destination:       "192.0.2.1:53",
		expectedInterface: expectedExternalInt,
		dialer:            nbnet.NewDialer(),
		expectedPacket:    createPacketExpectation("192.168.0.1", 12345, "192.0.2.1", 53),
	},

	{
		name:              "To duplicate internal route with custom dialer via physical interface",
		destination:       "10.0.0.2:53",
		expectedInterface: expectedInternalInt,
		dialer:            nbnet.NewDialer(),
		expectedPacket:    createPacketExpectation("192.168.1.1", 12345, "10.0.0.2", 53),
	},
	{
		name:              "To duplicate internal route without custom dialer via physical interface", // local route takes precedence
		destination:       "10.0.0.2:53",
		expectedInterface: expectedInternalInt,
		dialer:            &net.Dialer{},
		expectedPacket:    createPacketExpectation("192.168.1.1", 12345, "10.0.0.2", 53),
	},

	{
		name:              "To unique vpn route with custom dialer via physical interface",
		destination:       "172.16.0.2:53",
		expectedInterface: expectedExternalInt,
		dialer:            nbnet.NewDialer(),
		expectedPacket:    createPacketExpectation("192.168.0.1", 12345, "172.16.0.2", 53),
	},
	{
		name:              "To unique vpn route without custom dialer via vpn",
		destination:       "172.16.0.2:53",
		expectedInterface: expectedVPNint,
		dialer:            &net.Dialer{},
		expectedPacket:    createPacketExpectation("100.64.0.1", 12345, "172.16.0.2", 53),
	},
}

func TestRouting(t *testing.T) {
	for _, tc := range testCases {
		// todo resolve test execution on freebsd
		if runtime.GOOS == "freebsd" {
			t.Skip("skipping ", tc.name, " on freebsd")
		}
		t.Run(tc.name, func(t *testing.T) {
			setupTestEnv(t)

			filter := createBPFFilter(tc.destination)
			handle := startPacketCapture(t, tc.expectedInterface, filter)

			sendTestPacket(t, tc.destination, tc.expectedPacket.SrcPort, tc.dialer)

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			packet, err := packetSource.NextPacket()
			require.NoError(t, err)

			verifyPacket(t, packet, tc.expectedPacket)
		})
	}
}

func createPacketExpectation(srcIP string, srcPort int, dstIP string, dstPort int) PacketExpectation {
	return PacketExpectation{
		SrcIP:   net.ParseIP(srcIP),
		DstIP:   net.ParseIP(dstIP),
		SrcPort: srcPort,
		DstPort: dstPort,
		UDP:     true,
	}
}

func startPacketCapture(t *testing.T, intf, filter string) *pcap.Handle {
	t.Helper()

	inactive, err := pcap.NewInactiveHandle(intf)
	require.NoError(t, err, "Failed to create inactive pcap handle")
	defer inactive.CleanUp()

	err = inactive.SetSnapLen(1600)
	require.NoError(t, err, "Failed to set snap length on inactive handle")

	err = inactive.SetTimeout(time.Second * 10)
	require.NoError(t, err, "Failed to set timeout on inactive handle")

	err = inactive.SetImmediateMode(true)
	require.NoError(t, err, "Failed to set immediate mode on inactive handle")

	handle, err := inactive.Activate()
	require.NoError(t, err, "Failed to activate pcap handle")
	t.Cleanup(handle.Close)

	err = handle.SetBPFFilter(filter)
	require.NoError(t, err, "Failed to set BPF filter")

	return handle
}

func sendTestPacket(t *testing.T, destination string, sourcePort int, dialer dialer) {
	t.Helper()

	if dialer == nil {
		dialer = &net.Dialer{}
	}

	if sourcePort != 0 {
		localUDPAddr := &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: sourcePort,
		}
		switch dialer := dialer.(type) {
		case *nbnet.Dialer:
			dialer.LocalAddr = localUDPAddr
		case *net.Dialer:
			dialer.LocalAddr = localUDPAddr
		default:
			t.Fatal("Unsupported dialer type")
		}
	}

	msg := new(dns.Msg)
	msg.Id = dns.Id()
	msg.RecursionDesired = true
	msg.Question = []dns.Question{
		{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	conn, err := dialer.Dial("udp", destination)
	require.NoError(t, err, "Failed to dial UDP")
	defer conn.Close()

	data, err := msg.Pack()
	require.NoError(t, err, "Failed to pack DNS message")

	_, err = conn.Write(data)
	if err != nil {
		if strings.Contains(err.Error(), "required key not available") {
			t.Logf("Ignoring WireGuard key error: %v", err)
			return
		}
		t.Fatalf("Failed to send DNS query: %v", err)
	}
}

func createBPFFilter(destination string) string {
	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		return fmt.Sprintf("udp and dst host %s and dst port %s", host, port)
	}
	return "udp"
}

func verifyPacket(t *testing.T, packet gopacket.Packet, exp PacketExpectation) {
	t.Helper()

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	require.NotNil(t, ipLayer, "Expected IPv4 layer not found in packet")

	ip, ok := ipLayer.(*layers.IPv4)
	require.True(t, ok, "Failed to cast to IPv4 layer")

	// Convert both source and destination IP addresses to 16-byte representation
	expectedSrcIP := exp.SrcIP.To16()
	actualSrcIP := ip.SrcIP.To16()
	assert.Equal(t, expectedSrcIP, actualSrcIP, "Source IP mismatch")

	expectedDstIP := exp.DstIP.To16()
	actualDstIP := ip.DstIP.To16()
	assert.Equal(t, expectedDstIP, actualDstIP, "Destination IP mismatch")

	if exp.UDP {
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		require.NotNil(t, udpLayer, "Expected UDP layer not found in packet")

		udp, ok := udpLayer.(*layers.UDP)
		require.True(t, ok, "Failed to cast to UDP layer")

		assert.Equal(t, layers.UDPPort(exp.SrcPort), udp.SrcPort, "UDP source port mismatch")
		assert.Equal(t, layers.UDPPort(exp.DstPort), udp.DstPort, "UDP destination port mismatch")
	}

	if exp.TCP {
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		require.NotNil(t, tcpLayer, "Expected TCP layer not found in packet")

		tcp, ok := tcpLayer.(*layers.TCP)
		require.True(t, ok, "Failed to cast to TCP layer")

		assert.Equal(t, layers.TCPPort(exp.SrcPort), tcp.SrcPort, "TCP source port mismatch")
		assert.Equal(t, layers.TCPPort(exp.DstPort), tcp.DstPort, "TCP destination port mismatch")
	}
}

func createAndSetupDummyInterface(t *testing.T, intf string, ipAddressCIDR string) string {
	t.Helper()

	err := exec.Command("ifconfig", intf, "alias", ipAddressCIDR).Run()
	require.NoError(t, err, "Failed to create loopback alias")

	t.Cleanup(func() {
		err := exec.Command("ifconfig", intf, ipAddressCIDR, "-alias").Run()
		assert.NoError(t, err, "Failed to remove loopback alias")
	})

	return "lo0"
}

func addDummyRoute(t *testing.T, dstCIDR string, gw net.IP, _ string) {
	t.Helper()

	var originalNexthop net.IP
	if dstCIDR == "0.0.0.0/0" {
		var err error
		originalNexthop, err = fetchOriginalGateway()
		if err != nil {
			t.Logf("Failed to fetch original gateway: %v", err)
		}

		if output, err := exec.Command("route", "delete", "-net", dstCIDR).CombinedOutput(); err != nil {
			t.Logf("Failed to delete route: %v, output: %s", err, output)
		}
	}

	t.Cleanup(func() {
		if originalNexthop != nil {
			err := exec.Command("route", "add", "-net", dstCIDR, originalNexthop.String()).Run()
			assert.NoError(t, err, "Failed to restore original route")
		}
	})

	err := exec.Command("route", "add", "-net", dstCIDR, gw.String()).Run()
	require.NoError(t, err, "Failed to add route")

	t.Cleanup(func() {
		err := exec.Command("route", "delete", "-net", dstCIDR).Run()
		assert.NoError(t, err, "Failed to remove route")
	})
}

func fetchOriginalGateway() (net.IP, error) {
	output, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return nil, err
	}

	matches := regexp.MustCompile(`gateway: (\S+)`).FindStringSubmatch(string(output))
	if len(matches) == 0 {
		return nil, fmt.Errorf("gateway not found")
	}

	return net.ParseIP(matches[1]), nil
}

func setupDummyInterfacesAndRoutes(t *testing.T) {
	t.Helper()

	defaultDummy := createAndSetupDummyInterface(t, expectedExternalInt, "192.168.0.1/24")
	addDummyRoute(t, "0.0.0.0/0", net.IPv4(192, 168, 0, 1), defaultDummy)

	otherDummy := createAndSetupDummyInterface(t, expectedInternalInt, "192.168.1.1/24")
	addDummyRoute(t, "10.0.0.0/8", net.IPv4(192, 168, 1, 1), otherDummy)
}
