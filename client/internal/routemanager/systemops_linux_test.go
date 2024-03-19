//go:build !android

package routemanager

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	nbnet "github.com/netbirdio/netbird/util/net"
)

func TestEntryExists(t *testing.T) {
	tempDir := t.TempDir()
	tempFilePath := fmt.Sprintf("%s/rt_tables", tempDir)

	content := []string{
		"1000 reserved",
		fmt.Sprintf("%d %s", NetbirdVPNTableID, NetbirdVPNTableName),
		"9999 other_table",
	}
	require.NoError(t, os.WriteFile(tempFilePath, []byte(strings.Join(content, "\n")), 0644))

	file, err := os.Open(tempFilePath)
	require.NoError(t, err)
	defer func() {
		assert.NoError(t, file.Close())
	}()

	tests := []struct {
		name        string
		id          int
		shouldExist bool
		err         error
	}{
		{
			name:        "ExistsWithNetbirdPrefix",
			id:          7120,
			shouldExist: true,
			err:         nil,
		},
		{
			name:        "ExistsWithDifferentName",
			id:          1000,
			shouldExist: true,
			err:         ErrTableIDExists,
		},
		{
			name:        "DoesNotExist",
			id:          1234,
			shouldExist: false,
			err:         nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			exists, err := entryExists(file, tc.id)
			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tc.shouldExist, exists)
		})
	}
}

func createAndSetupDummyInterface(t *testing.T, interfaceName, ipAddressCIDR string) string {
	t.Helper()

	dummy := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: interfaceName}}
	err := netlink.LinkDel(dummy)
	if err != nil && !errors.Is(err, syscall.EINVAL) {
		t.Logf("Failed to delete dummy interface: %v", err)
	}

	err = netlink.LinkAdd(dummy)
	require.NoError(t, err)

	err = netlink.LinkSetUp(dummy)
	require.NoError(t, err)

	if ipAddressCIDR != "" {
		addr, err := netlink.ParseAddr(ipAddressCIDR)
		require.NoError(t, err)
		err = netlink.AddrAdd(dummy, addr)
		require.NoError(t, err)
	}

	t.Cleanup(func() {
		err := netlink.LinkDel(dummy)
		assert.NoError(t, err)
	})

	return dummy.Name
}

func addDummyRoute(t *testing.T, dstCIDR string, gw net.IP, intf string) {
	t.Helper()

	_, dstIPNet, err := net.ParseCIDR(dstCIDR)
	require.NoError(t, err)

	// Handle existing routes with metric 0
	if dstIPNet.String() == "0.0.0.0/0" {
		gw, linkIndex, err := fetchOriginalGateway(netlink.FAMILY_V4)
		if err != nil {
			t.Logf("Failed to fetch original gateway: %v", err)
		}

		// Handle existing routes with metric 0
		err = netlink.RouteDel(&netlink.Route{Dst: dstIPNet, Priority: 0})
		if err == nil {
			t.Cleanup(func() {
				err := netlink.RouteAdd(&netlink.Route{Dst: dstIPNet, Gw: gw, LinkIndex: linkIndex, Priority: 0})
				if err != nil && !errors.Is(err, syscall.EEXIST) {
					t.Fatalf("Failed to add route: %v", err)
				}
			})
		} else if !errors.Is(err, syscall.ESRCH) {
			t.Logf("Failed to delete route: %v", err)
		}
	}

	link, err := netlink.LinkByName(intf)
	require.NoError(t, err)
	linkIndex := link.Attrs().Index

	route := &netlink.Route{
		Dst:       dstIPNet,
		Gw:        gw,
		LinkIndex: linkIndex,
	}
	err = netlink.RouteDel(route)
	if err != nil && !errors.Is(err, syscall.ESRCH) {
		t.Logf("Failed to delete route: %v", err)
	}

	err = netlink.RouteAdd(route)
	if err != nil && !errors.Is(err, syscall.EEXIST) {
		t.Fatalf("Failed to add route: %v", err)
	}
	require.NoError(t, err)
}

func fetchOriginalGateway(family int) (net.IP, int, error) {
	routes, err := netlink.RouteList(nil, family)
	if err != nil {
		return nil, 0, err
	}

	for _, route := range routes {
		if route.Dst == nil {
			return route.Gw, route.LinkIndex, nil
		}
	}

	return nil, 0, fmt.Errorf("default route not found")
}

// TODO: move to unix file from here
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
		expectedInterface: "wgtest0",
		dialer:            &net.Dialer{},
		expectedPacket:    createPacketExpectation("100.64.0.1", 12345, "192.0.2.1", 53),
	},
	{
		name:              "To external host with custom dialer via physical interface",
		destination:       "192.0.2.1:53",
		expectedInterface: "dummyext0",
		dialer:            nbnet.NewDialer(),
		expectedPacket:    createPacketExpectation("192.168.0.1", 12345, "192.0.2.1", 53),
	},

	{
		name:              "To duplicate internal route with custom dialer via physical interface",
		destination:       "10.0.0.2:53",
		expectedInterface: "dummyint0",
		dialer:            nbnet.NewDialer(),
		expectedPacket:    createPacketExpectation("192.168.1.1", 12345, "10.0.0.2", 53),
	},
	{
		name:              "To duplicate internal route without custom dialer via physical interface", // local route takes precedence
		destination:       "10.0.0.2:53",
		expectedInterface: "dummyint0",
		dialer:            &net.Dialer{},
		expectedPacket:    createPacketExpectation("192.168.1.1", 12345, "10.0.0.2", 53),
	},

	{
		name:              "To unique vpn route with custom dialer via physical interface",
		destination:       "172.16.0.2:53",
		expectedInterface: "dummyext0",
		dialer:            nbnet.NewDialer(),
		expectedPacket:    createPacketExpectation("192.168.0.1", 12345, "172.16.0.2", 53),
	},
	{
		name:              "To unique vpn route without custom dialer via vpn",
		destination:       "172.16.0.2:53",
		expectedInterface: "wgtest0",
		dialer:            &net.Dialer{},
		expectedPacket:    createPacketExpectation("100.64.0.1", 12345, "172.16.0.2", 53),
	},

	{
		name:              "To more specific route without custom dialer via physical interface",
		destination:       "10.10.0.2:53",
		expectedInterface: "dummyint0",
		dialer:            &net.Dialer{},
		expectedPacket:    createPacketExpectation("192.168.1.1", 12345, "10.10.0.2", 53),
	},

	{
		name:              "To more specific route (local) without custom dialer via physical interface",
		destination:       "127.0.10.1:53",
		expectedInterface: "lo",
		dialer:            &net.Dialer{},
		expectedPacket:    createPacketExpectation("127.0.0.1", 12345, "127.0.10.1", 53),
	},
}

func TestRouting(t *testing.T) {
	for _, tc := range testCases {
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

func setupDummyInterfacesAndRoutes(t *testing.T) {
	t.Helper()

	defaultDummy := createAndSetupDummyInterface(t, "dummyext0", "192.168.0.1/24")
	addDummyRoute(t, "0.0.0.0/0", net.IPv4(192, 168, 0, 1), defaultDummy)

	otherDummy := createAndSetupDummyInterface(t, "dummyint0", "192.168.1.1/24")
	addDummyRoute(t, "10.0.0.0/8", net.IPv4(192, 168, 1, 1), otherDummy)
}
