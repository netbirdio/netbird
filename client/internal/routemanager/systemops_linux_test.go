//go:build !android

package routemanager

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
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
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/netbirdio/netbird/client/internal/stdnet"
	"github.com/netbirdio/netbird/iface"
	nbnet "github.com/netbirdio/netbird/util/net"
)

type dialer interface {
	Dial(network, address string) (net.Conn, error)
}

type PacketExpectation struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort int
	DstPort int
	UDP     bool
	TCP     bool
}

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

func TestRoutingWithTables(t *testing.T) {
	testCases := []struct {
		name              string
		destination       string
		captureInterface  string
		dialer            dialer
		packetExpectation PacketExpectation
	}{
		{
			name:              "To external host without fwmark via vpn",
			destination:       "192.0.2.1:53",
			captureInterface:  "wgtest0",
			dialer:            &net.Dialer{},
			packetExpectation: createPacketExpectation("100.64.0.1", 12345, "192.0.2.1", 53),
		},
		{
			name:              "To external host with fwmark via physical interface",
			destination:       "192.0.2.1:53",
			captureInterface:  "dummyext0",
			dialer:            nbnet.NewDialer(),
			packetExpectation: createPacketExpectation("192.168.0.1", 12345, "192.0.2.1", 53),
		},

		{
			name:              "To duplicate internal route with fwmark via physical interface",
			destination:       "10.0.0.1:53",
			captureInterface:  "dummyint0",
			dialer:            nbnet.NewDialer(),
			packetExpectation: createPacketExpectation("192.168.1.1", 12345, "10.0.0.1", 53),
		},
		{
			name:              "To duplicate internal route without fwmark via physical interface", // local route takes precedence
			destination:       "10.0.0.1:53",
			captureInterface:  "dummyint0",
			dialer:            &net.Dialer{},
			packetExpectation: createPacketExpectation("192.168.1.1", 12345, "10.0.0.1", 53),
		},

		{
			name:              "To unique vpn route with fwmark via physical interface",
			destination:       "172.16.0.1:53",
			captureInterface:  "dummyext0",
			dialer:            nbnet.NewDialer(),
			packetExpectation: createPacketExpectation("192.168.0.1", 12345, "172.16.0.1", 53),
		},
		{
			name:              "To unique vpn route without fwmark via vpn",
			destination:       "172.16.0.1:53",
			captureInterface:  "wgtest0",
			dialer:            &net.Dialer{},
			packetExpectation: createPacketExpectation("100.64.0.1", 12345, "172.16.0.1", 53),
		},

		{
			name:              "To more specific route without fwmark via vpn interface",
			destination:       "10.10.0.1:53",
			captureInterface:  "dummyint0",
			dialer:            &net.Dialer{},
			packetExpectation: createPacketExpectation("192.168.1.1", 12345, "10.10.0.1", 53),
		},

		{
			name:              "To more specific route (local) without fwmark via physical interface",
			destination:       "127.0.10.1:53",
			captureInterface:  "lo",
			dialer:            &net.Dialer{},
			packetExpectation: createPacketExpectation("127.0.0.1", 12345, "127.0.10.1", 53),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			wgIface, _, _ := setupTestEnv(t)

			// default route exists in main table and vpn table
			err := addToRouteTableIfNoExists(netip.MustParsePrefix("0.0.0.0/0"), wgIface.Address().IP.String(), wgIface.Name())
			require.NoError(t, err, "addToRouteTableIfNoExists should not return err")

			// 10.0.0.0/8 route exists in main table and vpn table
			err = addToRouteTableIfNoExists(netip.MustParsePrefix("10.0.0.0/8"), wgIface.Address().IP.String(), wgIface.Name())
			require.NoError(t, err, "addToRouteTableIfNoExists should not return err")

			// 10.10.0.0/24 more specific route exists in vpn table
			err = addToRouteTableIfNoExists(netip.MustParsePrefix("10.10.0.0/24"), wgIface.Address().IP.String(), wgIface.Name())
			require.NoError(t, err, "addToRouteTableIfNoExists should not return err")

			// 127.0.10.0/24 more specific route exists in vpn table
			err = addToRouteTableIfNoExists(netip.MustParsePrefix("127.0.10.0/24"), wgIface.Address().IP.String(), wgIface.Name())
			require.NoError(t, err, "addToRouteTableIfNoExists should not return err")

			// unique route in vpn table
			err = addToRouteTableIfNoExists(netip.MustParsePrefix("172.16.0.0/16"), wgIface.Address().IP.String(), wgIface.Name())
			require.NoError(t, err, "addToRouteTableIfNoExists should not return err")

			filter := createBPFFilter(tc.destination)
			handle := startPacketCapture(t, tc.captureInterface, filter)

			sendTestPacket(t, tc.destination, tc.packetExpectation.SrcPort, tc.dialer)

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			packet, err := packetSource.NextPacket()
			require.NoError(t, err)

			verifyPacket(t, packet, tc.packetExpectation)
		})
	}
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

func createAndSetupDummyInterface(t *testing.T, interfaceName, ipAddressCIDR string) *netlink.Dummy {
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

	return dummy
}

func addDummyRoute(t *testing.T, dstCIDR string, gw net.IP, linkIndex int) {
	t.Helper()

	_, dstIPNet, err := net.ParseCIDR(dstCIDR)
	require.NoError(t, err)

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
}

// fetchOriginalGateway returns the original gateway IP address and the interface index.
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

func setupDummyInterfacesAndRoutes(t *testing.T) (string, string) {
	t.Helper()

	defaultDummy := createAndSetupDummyInterface(t, "dummyext0", "192.168.0.1/24")
	addDummyRoute(t, "0.0.0.0/0", net.IPv4(192, 168, 0, 1), defaultDummy.Attrs().Index)

	otherDummy := createAndSetupDummyInterface(t, "dummyint0", "192.168.1.1/24")
	addDummyRoute(t, "10.0.0.0/8", nil, otherDummy.Attrs().Index)

	t.Cleanup(func() {
		err := netlink.LinkDel(defaultDummy)
		assert.NoError(t, err)
		err = netlink.LinkDel(otherDummy)
		assert.NoError(t, err)
	})

	return defaultDummy.Name, otherDummy.Name
}

func createWGInterface(t *testing.T, interfaceName, ipAddressCIDR string, listenPort int) *iface.WGIface {
	t.Helper()

	peerPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	newNet, err := stdnet.NewNet(nil)
	require.NoError(t, err)

	wgInterface, err := iface.NewWGIFace(interfaceName, ipAddressCIDR, listenPort, peerPrivateKey.String(), iface.DefaultMTU, newNet, nil)
	require.NoError(t, err, "should create testing WireGuard interface")

	err = wgInterface.Create()
	require.NoError(t, err, "should create testing WireGuard interface")

	t.Cleanup(func() {
		wgInterface.Close()
	})

	return wgInterface
}

func setupTestEnv(t *testing.T) (*iface.WGIface, string, string) {
	t.Helper()

	defaultDummy, otherDummy := setupDummyInterfacesAndRoutes(t)

	wgIface := createWGInterface(t, "wgtest0", "100.64.0.1/24", 51820)
	t.Cleanup(func() {
		assert.NoError(t, wgIface.Close())
	})

	_, _, err := setupRouting(nil, nil)
	require.NoError(t, err, "setupRouting should not return err")
	t.Cleanup(func() {
		assert.NoError(t, cleanupRouting())
	})

	return wgIface, defaultDummy, otherDummy
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

func createPacketExpectation(srcIP string, srcPort int, dstIP string, dstPort int) PacketExpectation {
	return PacketExpectation{
		SrcIP:   net.ParseIP(srcIP),
		DstIP:   net.ParseIP(dstIP),
		SrcPort: srcPort,
		DstPort: dstPort,
		UDP:     true,
	}
}
