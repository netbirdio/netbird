package uspfilter

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	wgdevice "golang.zx2c4.com/wireguard/device"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/conntrack"
	"github.com/netbirdio/netbird/client/firewall/uspfilter/log"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/netflow"
	"github.com/netbirdio/netbird/management/domain"
)

var logger = log.NewFromLogrus(logrus.StandardLogger())
var flowLogger = netflow.NewManager(nil, []byte{}, nil).GetLogger()

type IFaceMock struct {
	SetFilterFunc   func(device.PacketFilter) error
	AddressFunc     func() wgaddr.Address
	GetWGDeviceFunc func() *wgdevice.Device
	GetDeviceFunc   func() *device.FilteredDevice
}

func (i *IFaceMock) GetWGDevice() *wgdevice.Device {
	if i.GetWGDeviceFunc == nil {
		return nil
	}
	return i.GetWGDeviceFunc()
}

func (i *IFaceMock) GetDevice() *device.FilteredDevice {
	if i.GetDeviceFunc == nil {
		return nil
	}
	return i.GetDeviceFunc()
}

func (i *IFaceMock) SetFilter(iface device.PacketFilter) error {
	if i.SetFilterFunc == nil {
		return fmt.Errorf("not implemented")
	}
	return i.SetFilterFunc(iface)
}

func (i *IFaceMock) Address() wgaddr.Address {
	if i.AddressFunc == nil {
		return wgaddr.Address{}
	}
	return i.AddressFunc()
}

func TestManagerCreate(t *testing.T) {
	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}

	m, err := Create(ifaceMock, false, flowLogger)
	if err != nil {
		t.Errorf("failed to create Manager: %v", err)
		return
	}

	if m == nil {
		t.Error("Manager is nil")
	}
}

func TestManagerAddPeerFiltering(t *testing.T) {
	isSetFilterCalled := false
	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error {
			isSetFilterCalled = true
			return nil
		},
	}

	m, err := Create(ifaceMock, false, flowLogger)
	if err != nil {
		t.Errorf("failed to create Manager: %v", err)
		return
	}

	ip := net.ParseIP("192.168.1.1")
	proto := fw.ProtocolTCP
	port := &fw.Port{Values: []uint16{80}}
	action := fw.ActionDrop

	rule, err := m.AddPeerFiltering(nil, ip, proto, nil, port, action, "")
	if err != nil {
		t.Errorf("failed to add filtering: %v", err)
		return
	}

	if rule == nil {
		t.Error("Rule is nil")
		return
	}

	if !isSetFilterCalled {
		t.Error("SetFilter was not called")
		return
	}
}

func TestManagerDeleteRule(t *testing.T) {
	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}

	m, err := Create(ifaceMock, false, flowLogger)
	if err != nil {
		t.Errorf("failed to create Manager: %v", err)
		return
	}

	ip := netip.MustParseAddr("192.168.1.1")
	proto := fw.ProtocolTCP
	port := &fw.Port{Values: []uint16{80}}
	action := fw.ActionDrop

	rule2, err := m.AddPeerFiltering(nil, ip.AsSlice(), proto, nil, port, action, "")
	if err != nil {
		t.Errorf("failed to add filtering: %v", err)
		return
	}

	for _, r := range rule2 {
		if _, ok := m.incomingRules[ip][r.ID()]; !ok {
			t.Errorf("rule2 is not in the incomingRules")
		}
	}

	for _, r := range rule2 {
		err = m.DeletePeerRule(r)
		if err != nil {
			t.Errorf("failed to delete rule: %v", err)
			return
		}
	}

	for _, r := range rule2 {
		if _, ok := m.incomingRules[ip][r.ID()]; ok {
			t.Errorf("rule2 is not in the incomingRules")
		}
	}
}

func TestAddUDPPacketHook(t *testing.T) {
	tests := []struct {
		name       string
		in         bool
		expDir     fw.RuleDirection
		ip         netip.Addr
		dPort      uint16
		hook       func([]byte) bool
		expectedID string
	}{
		{
			name:   "Test Outgoing UDP Packet Hook",
			in:     false,
			expDir: fw.RuleDirectionOUT,
			ip:     netip.MustParseAddr("10.168.0.1"),
			dPort:  8000,
			hook:   func([]byte) bool { return true },
		},
		{
			name:   "Test Incoming UDP Packet Hook",
			in:     true,
			expDir: fw.RuleDirectionIN,
			ip:     netip.MustParseAddr("::1"),
			dPort:  9000,
			hook:   func([]byte) bool { return false },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := Create(&IFaceMock{
				SetFilterFunc: func(device.PacketFilter) error { return nil },
			}, false, flowLogger)
			require.NoError(t, err)

			manager.AddUDPPacketHook(tt.in, tt.ip, tt.dPort, tt.hook)

			var addedRule PeerRule
			if tt.in {
				if len(manager.incomingRules[tt.ip]) != 1 {
					t.Errorf("expected 1 incoming rule, got %d", len(manager.incomingRules))
					return
				}
				for _, rule := range manager.incomingRules[tt.ip] {
					addedRule = rule
				}
			} else {
				if len(manager.outgoingRules) != 1 {
					t.Errorf("expected 1 outgoing rule, got %d", len(manager.outgoingRules))
					return
				}
				for _, rule := range manager.outgoingRules[tt.ip] {
					addedRule = rule
				}
			}

			if tt.ip.Compare(addedRule.ip) != 0 {
				t.Errorf("expected ip %s, got %s", tt.ip, addedRule.ip)
				return
			}
			if tt.dPort != addedRule.dPort.Values[0] {
				t.Errorf("expected dPort %d, got %d", tt.dPort, addedRule.dPort.Values[0])
				return
			}
			if layers.LayerTypeUDP != addedRule.protoLayer {
				t.Errorf("expected protoLayer %s, got %s", layers.LayerTypeUDP, addedRule.protoLayer)
				return
			}
			if addedRule.udpHook == nil {
				t.Errorf("expected udpHook to be set")
				return
			}
		})
	}
}

func TestManagerReset(t *testing.T) {
	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}

	m, err := Create(ifaceMock, false, flowLogger)
	if err != nil {
		t.Errorf("failed to create Manager: %v", err)
		return
	}

	ip := net.ParseIP("192.168.1.1")
	proto := fw.ProtocolTCP
	port := &fw.Port{Values: []uint16{80}}
	action := fw.ActionDrop

	_, err = m.AddPeerFiltering(nil, ip, proto, nil, port, action, "")
	if err != nil {
		t.Errorf("failed to add filtering: %v", err)
		return
	}

	err = m.Close(nil)
	if err != nil {
		t.Errorf("failed to reset Manager: %v", err)
		return
	}

	if len(m.outgoingRules) != 0 || len(m.incomingRules) != 0 {
		t.Errorf("rules is not empty")
	}
}

func TestNotMatchByIP(t *testing.T) {
	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.10.0.100"),
				Network: netip.MustParsePrefix("100.10.0.0/16"),
			}
		},
	}

	m, err := Create(ifaceMock, false, flowLogger)
	if err != nil {
		t.Errorf("failed to create Manager: %v", err)
		return
	}

	ip := net.ParseIP("0.0.0.0")
	proto := fw.ProtocolUDP
	action := fw.ActionAccept

	_, err = m.AddPeerFiltering(nil, ip, proto, nil, nil, action, "")
	if err != nil {
		t.Errorf("failed to add filtering: %v", err)
		return
	}

	ipv4 := &layers.IPv4{
		TTL:      64,
		Version:  4,
		SrcIP:    net.ParseIP("100.10.0.1"),
		DstIP:    net.ParseIP("100.10.0.100"),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 51334,
		DstPort: 53,
	}

	if err := udp.SetNetworkLayerForChecksum(ipv4); err != nil {
		t.Errorf("failed to set network layer for checksum: %v", err)
		return
	}
	payload := gopacket.Payload("test")

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err = gopacket.SerializeLayers(buf, opts, ipv4, udp, payload); err != nil {
		t.Errorf("failed to serialize packet: %v", err)
		return
	}

	if m.filterInbound(buf.Bytes(), 0) {
		t.Errorf("expected packet to be accepted")
		return
	}

	if err = m.Close(nil); err != nil {
		t.Errorf("failed to reset Manager: %v", err)
		return
	}
}

// TestRemovePacketHook tests the functionality of the RemovePacketHook method
func TestRemovePacketHook(t *testing.T) {
	// creating mock iface
	iface := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}

	// creating manager instance
	manager, err := Create(iface, false, flowLogger)
	if err != nil {
		t.Fatalf("Failed to create Manager: %s", err)
	}
	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	// Add a UDP packet hook
	hookFunc := func(data []byte) bool { return true }
	hookID := manager.AddUDPPacketHook(false, netip.MustParseAddr("192.168.0.1"), 8080, hookFunc)

	// Assert the hook is added by finding it in the manager's outgoing rules
	found := false
	for _, arr := range manager.outgoingRules {
		for _, rule := range arr {
			if rule.id == hookID {
				found = true
				break
			}
		}
	}

	if !found {
		t.Fatalf("The hook was not added properly.")
	}

	// Now remove the packet hook
	err = manager.RemovePacketHook(hookID)
	if err != nil {
		t.Fatalf("Failed to remove hook: %s", err)
	}

	// Assert the hook is removed by checking it in the manager's outgoing rules
	for _, arr := range manager.outgoingRules {
		for _, rule := range arr {
			if rule.id == hookID {
				t.Fatalf("The hook was not removed properly.")
			}
		}
	}
}

func TestProcessOutgoingHooks(t *testing.T) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger)
	require.NoError(t, err)

	manager.udpTracker.Close()
	manager.udpTracker = conntrack.NewUDPTracker(100*time.Millisecond, logger, flowLogger)
	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	manager.decoders = sync.Pool{
		New: func() any {
			d := &decoder{
				decoded: []gopacket.LayerType{},
			}
			d.parser = gopacket.NewDecodingLayerParser(
				layers.LayerTypeIPv4,
				&d.eth, &d.ip4, &d.ip6, &d.icmp4, &d.icmp6, &d.tcp, &d.udp,
			)
			d.parser.IgnoreUnsupported = true
			return d
		},
	}

	hookCalled := false
	hookID := manager.AddUDPPacketHook(
		false,
		netip.MustParseAddr("100.10.0.100"),
		53,
		func([]byte) bool {
			hookCalled = true
			return true
		},
	)
	require.NotEmpty(t, hookID)

	// Create test UDP packet
	ipv4 := &layers.IPv4{
		TTL:      64,
		Version:  4,
		SrcIP:    net.ParseIP("100.10.0.1"),
		DstIP:    net.ParseIP("100.10.0.100"),
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: 51334,
		DstPort: 53,
	}

	err = udp.SetNetworkLayerForChecksum(ipv4)
	require.NoError(t, err)
	payload := gopacket.Payload("test")

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	err = gopacket.SerializeLayers(buf, opts, ipv4, udp, payload)
	require.NoError(t, err)

	// Test hook gets called
	result := manager.filterOutbound(buf.Bytes(), 0)
	require.True(t, result)
	require.True(t, hookCalled)

	// Test non-UDP packet is ignored
	ipv4.Protocol = layers.IPProtocolTCP
	buf = gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buf, opts, ipv4)
	require.NoError(t, err)

	result = manager.filterOutbound(buf.Bytes(), 0)
	require.False(t, result)
}

func TestUSPFilterCreatePerformance(t *testing.T) {
	for _, testMax := range []int{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000} {
		t.Run(fmt.Sprintf("Testing %d rules", testMax), func(t *testing.T) {
			// just check on the local interface
			ifaceMock := &IFaceMock{
				SetFilterFunc: func(device.PacketFilter) error { return nil },
			}
			manager, err := Create(ifaceMock, false, flowLogger)
			require.NoError(t, err)
			time.Sleep(time.Second)

			defer func() {
				if err := manager.Close(nil); err != nil {
					t.Errorf("clear the manager state: %v", err)
				}
				time.Sleep(time.Second)
			}()

			ip := net.ParseIP("10.20.0.100")
			start := time.Now()
			for i := 0; i < testMax; i++ {
				port := &fw.Port{Values: []uint16{uint16(1000 + i)}}
				_, err = manager.AddPeerFiltering(nil, ip, "tcp", nil, port, fw.ActionAccept, "")

				require.NoError(t, err, "failed to add rule")
			}
			t.Logf("execution avg per rule: %s", time.Since(start)/time.Duration(testMax))
		})
	}
}

func TestStatefulFirewall_UDPTracking(t *testing.T) {
	manager, err := Create(&IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}, false, flowLogger)
	require.NoError(t, err)

	manager.udpTracker.Close() // Close the existing tracker
	manager.udpTracker = conntrack.NewUDPTracker(200*time.Millisecond, logger, flowLogger)
	manager.decoders = sync.Pool{
		New: func() any {
			d := &decoder{
				decoded: []gopacket.LayerType{},
			}
			d.parser = gopacket.NewDecodingLayerParser(
				layers.LayerTypeIPv4,
				&d.eth, &d.ip4, &d.ip6, &d.icmp4, &d.icmp6, &d.tcp, &d.udp,
			)
			d.parser.IgnoreUnsupported = true
			return d
		},
	}
	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	// Set up packet parameters
	srcIP := netip.MustParseAddr("100.10.0.1")
	dstIP := netip.MustParseAddr("100.10.0.100")
	srcPort := uint16(51334)
	dstPort := uint16(53)

	// Create outbound packet
	outboundIPv4 := &layers.IPv4{
		TTL:      64,
		Version:  4,
		SrcIP:    srcIP.AsSlice(),
		DstIP:    dstIP.AsSlice(),
		Protocol: layers.IPProtocolUDP,
	}
	outboundUDP := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}

	err = outboundUDP.SetNetworkLayerForChecksum(outboundIPv4)
	require.NoError(t, err)

	outboundBuf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err = gopacket.SerializeLayers(outboundBuf, opts,
		outboundIPv4,
		outboundUDP,
		gopacket.Payload("test"),
	)
	require.NoError(t, err)

	// Process outbound packet and verify connection tracking
	drop := manager.FilterOutbound(outboundBuf.Bytes(), 0)
	require.False(t, drop, "Initial outbound packet should not be dropped")

	// Verify connection was tracked
	conn, exists := manager.udpTracker.GetConnection(srcIP, srcPort, dstIP, dstPort)

	require.True(t, exists, "Connection should be tracked after outbound packet")
	require.True(t, srcIP.Compare(conn.SourceIP) == 0, "Source IP should match")
	require.True(t, dstIP.Compare(conn.DestIP) == 0, "Destination IP should match")
	require.Equal(t, srcPort, conn.SourcePort, "Source port should match")
	require.Equal(t, dstPort, conn.DestPort, "Destination port should match")

	// Create valid inbound response packet
	inboundIPv4 := &layers.IPv4{
		TTL:      64,
		Version:  4,
		SrcIP:    dstIP.AsSlice(), // Original destination is now source
		DstIP:    srcIP.AsSlice(), // Original source is now destination
		Protocol: layers.IPProtocolUDP,
	}
	inboundUDP := &layers.UDP{
		SrcPort: layers.UDPPort(dstPort), // Original destination port is now source
		DstPort: layers.UDPPort(srcPort), // Original source port is now destination
	}

	err = inboundUDP.SetNetworkLayerForChecksum(inboundIPv4)
	require.NoError(t, err)

	inboundBuf := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(inboundBuf, opts,
		inboundIPv4,
		inboundUDP,
		gopacket.Payload("response"),
	)
	require.NoError(t, err)
	// Test roundtrip response handling over time
	checkPoints := []struct {
		sleep       time.Duration
		shouldAllow bool
		description string
	}{
		{
			sleep:       0,
			shouldAllow: true,
			description: "Immediate response should be allowed",
		},
		{
			sleep:       50 * time.Millisecond,
			shouldAllow: true,
			description: "Response within timeout should be allowed",
		},
		{
			sleep:       100 * time.Millisecond,
			shouldAllow: true,
			description: "Response at half timeout should be allowed",
		},
		{
			// tracker hasn't updated conn for 250ms -> greater than 200ms timeout
			sleep:       250 * time.Millisecond,
			shouldAllow: false,
			description: "Response after timeout should be dropped",
		},
	}

	for _, cp := range checkPoints {
		time.Sleep(cp.sleep)

		drop = manager.filterInbound(inboundBuf.Bytes(), 0)
		require.Equal(t, cp.shouldAllow, !drop, cp.description)

		// If the connection should still be valid, verify it exists
		if cp.shouldAllow {
			conn, exists := manager.udpTracker.GetConnection(srcIP, srcPort, dstIP, dstPort)
			require.True(t, exists, "Connection should still exist during valid window")
			require.True(t, time.Since(conn.GetLastSeen()) < manager.udpTracker.Timeout(),
				"LastSeen should be updated for valid responses")
		}
	}

	// Test invalid response packets (while connection is expired)
	invalidCases := []struct {
		name        string
		modifyFunc  func(*layers.IPv4, *layers.UDP)
		description string
	}{
		{
			name: "wrong source IP",
			modifyFunc: func(ip *layers.IPv4, udp *layers.UDP) {
				ip.SrcIP = net.ParseIP("100.10.0.101")
			},
			description: "Response from wrong IP should be dropped",
		},
		{
			name: "wrong destination IP",
			modifyFunc: func(ip *layers.IPv4, udp *layers.UDP) {
				ip.DstIP = net.ParseIP("100.10.0.2")
			},
			description: "Response to wrong IP should be dropped",
		},
		{
			name: "wrong source port",
			modifyFunc: func(ip *layers.IPv4, udp *layers.UDP) {
				udp.SrcPort = 54
			},
			description: "Response from wrong port should be dropped",
		},
		{
			name: "wrong destination port",
			modifyFunc: func(ip *layers.IPv4, udp *layers.UDP) {
				udp.DstPort = 51335
			},
			description: "Response to wrong port should be dropped",
		},
	}

	// Create a new outbound connection for invalid tests
	drop = manager.filterOutbound(outboundBuf.Bytes(), 0)
	require.False(t, drop, "Second outbound packet should not be dropped")

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			testIPv4 := *inboundIPv4
			testUDP := *inboundUDP

			tc.modifyFunc(&testIPv4, &testUDP)

			err = testUDP.SetNetworkLayerForChecksum(&testIPv4)
			require.NoError(t, err)

			testBuf := gopacket.NewSerializeBuffer()
			err = gopacket.SerializeLayers(testBuf, opts,
				&testIPv4,
				&testUDP,
				gopacket.Payload("response"),
			)
			require.NoError(t, err)

			// Verify the invalid packet is dropped
			drop = manager.filterInbound(testBuf.Bytes(), 0)
			require.True(t, drop, tc.description)
		})
	}
}

func TestUpdateSetMerge(t *testing.T) {
	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}

	manager, err := Create(ifaceMock, false, flowLogger)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil))
	})

	set := fw.NewDomainSet(domain.List{"example.org"})

	initialPrefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("192.168.1.0/24"),
	}

	rule, err := manager.AddRouteFiltering(
		nil,
		[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		fw.Network{Set: set},
		fw.ProtocolTCP,
		nil,
		nil,
		fw.ActionAccept,
	)
	require.NoError(t, err)
	require.NotNil(t, rule)

	// Update the set with initial prefixes
	err = manager.UpdateSet(set, initialPrefixes)
	require.NoError(t, err)

	// Test initial prefixes work
	srcIP := netip.MustParseAddr("100.10.0.1")
	dstIP1 := netip.MustParseAddr("10.0.0.100")
	dstIP2 := netip.MustParseAddr("192.168.1.100")
	dstIP3 := netip.MustParseAddr("172.16.0.100")

	_, isAllowed1 := manager.routeACLsPass(srcIP, dstIP1, protoToLayer(fw.ProtocolTCP, layers.LayerTypeIPv4), 12345, 80)
	_, isAllowed2 := manager.routeACLsPass(srcIP, dstIP2, protoToLayer(fw.ProtocolTCP, layers.LayerTypeIPv4), 12345, 80)
	_, isAllowed3 := manager.routeACLsPass(srcIP, dstIP3, protoToLayer(fw.ProtocolTCP, layers.LayerTypeIPv4), 12345, 80)

	require.True(t, isAllowed1, "Traffic to 10.0.0.100 should be allowed")
	require.True(t, isAllowed2, "Traffic to 192.168.1.100 should be allowed")
	require.False(t, isAllowed3, "Traffic to 172.16.0.100 should be denied")

	newPrefixes := []netip.Prefix{
		netip.MustParsePrefix("172.16.0.0/16"),
		netip.MustParsePrefix("10.1.0.0/24"),
	}

	err = manager.UpdateSet(set, newPrefixes)
	require.NoError(t, err)

	// Check that all original prefixes are still included
	_, isAllowed1 = manager.routeACLsPass(srcIP, dstIP1, protoToLayer(fw.ProtocolTCP, layers.LayerTypeIPv4), 12345, 80)
	_, isAllowed2 = manager.routeACLsPass(srcIP, dstIP2, protoToLayer(fw.ProtocolTCP, layers.LayerTypeIPv4), 12345, 80)
	require.True(t, isAllowed1, "Traffic to 10.0.0.100 should still be allowed after update")
	require.True(t, isAllowed2, "Traffic to 192.168.1.100 should still be allowed after update")

	// Check that new prefixes are included
	dstIP4 := netip.MustParseAddr("172.16.1.100")
	dstIP5 := netip.MustParseAddr("10.1.0.50")

	_, isAllowed4 := manager.routeACLsPass(srcIP, dstIP4, protoToLayer(fw.ProtocolTCP, layers.LayerTypeIPv4), 12345, 80)
	_, isAllowed5 := manager.routeACLsPass(srcIP, dstIP5, protoToLayer(fw.ProtocolTCP, layers.LayerTypeIPv4), 12345, 80)

	require.True(t, isAllowed4, "Traffic to new prefix 172.16.0.0/16 should be allowed")
	require.True(t, isAllowed5, "Traffic to new prefix 10.1.0.0/24 should be allowed")

	// Verify the rule has all prefixes
	manager.mutex.RLock()
	foundRule := false
	for _, r := range manager.routeRules {
		if r.id == rule.ID() {
			foundRule = true
			require.Len(t, r.destinations, len(initialPrefixes)+len(newPrefixes),
				"Rule should have all prefixes merged")
		}
	}
	manager.mutex.RUnlock()
	require.True(t, foundRule, "Rule should be found")
}

func TestUpdateSetDeduplication(t *testing.T) {
	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
	}

	manager, err := Create(ifaceMock, false, flowLogger)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil))
	})

	set := fw.NewDomainSet(domain.List{"example.org"})

	rule, err := manager.AddRouteFiltering(
		nil,
		[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		fw.Network{Set: set},
		fw.ProtocolTCP,
		nil,
		nil,
		fw.ActionAccept,
	)
	require.NoError(t, err)
	require.NotNil(t, rule)

	initialPrefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.0.0/24"), // Duplicate
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("192.168.1.0/24"), // Duplicate
	}

	err = manager.UpdateSet(set, initialPrefixes)
	require.NoError(t, err)

	// Check the internal state for deduplication
	manager.mutex.RLock()
	foundRule := false
	for _, r := range manager.routeRules {
		if r.id == rule.ID() {
			foundRule = true
			// Should have deduplicated to 2 prefixes
			require.Len(t, r.destinations, 2, "Duplicate prefixes should be removed")

			// Check the prefixes are correct
			expectedPrefixes := []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.1.0/24"),
			}
			for i, prefix := range expectedPrefixes {
				require.True(t, r.destinations[i] == prefix,
					"Prefix should match expected value")
			}
		}
	}
	manager.mutex.RUnlock()
	require.True(t, foundRule, "Rule should be found")

	// Test with overlapping prefixes of different sizes
	overlappingPrefixes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/16"),    // More general
		netip.MustParsePrefix("10.0.0.0/24"),    // More specific (already exists)
		netip.MustParsePrefix("192.168.0.0/16"), // More general
		netip.MustParsePrefix("192.168.1.0/24"), // More specific (already exists)
	}

	err = manager.UpdateSet(set, overlappingPrefixes)
	require.NoError(t, err)

	// Check that all prefixes are included (no deduplication of overlapping prefixes)
	manager.mutex.RLock()
	for _, r := range manager.routeRules {
		if r.id == rule.ID() {
			// Should have all 4 prefixes (2 original + 2 new more general ones)
			require.Len(t, r.destinations, 4,
				"Overlapping prefixes should not be deduplicated")

			// Verify they're sorted correctly (more specific prefixes should come first)
			prefixes := make([]string, 0, len(r.destinations))
			for _, p := range r.destinations {
				prefixes = append(prefixes, p.String())
			}

			// Check sorted order
			require.Equal(t, []string{
				"10.0.0.0/16",
				"10.0.0.0/24",
				"192.168.0.0/16",
				"192.168.1.0/24",
			}, prefixes, "Prefixes should be sorted")
		}
	}
	manager.mutex.RUnlock()

	// Test functionality with all prefixes
	testCases := []struct {
		dstIP    netip.Addr
		expected bool
		desc     string
	}{
		{netip.MustParseAddr("10.0.0.100"), true, "IP in both /16 and /24"},
		{netip.MustParseAddr("10.0.1.100"), true, "IP only in /16"},
		{netip.MustParseAddr("192.168.1.100"), true, "IP in both /16 and /24"},
		{netip.MustParseAddr("192.168.2.100"), true, "IP only in /16"},
		{netip.MustParseAddr("172.16.0.100"), false, "IP not in any prefix"},
	}

	srcIP := netip.MustParseAddr("100.10.0.1")
	for _, tc := range testCases {
		_, isAllowed := manager.routeACLsPass(srcIP, tc.dstIP, protoToLayer(fw.ProtocolTCP, layers.LayerTypeIPv4), 12345, 80)
		require.Equal(t, tc.expected, isAllowed, tc.desc)
	}
}
