package uspfilter

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/iface"
)

type IFaceMock struct {
	SetFilterFunc func(iface.PacketFilter) error
}

func (i *IFaceMock) SetFilter(iface iface.PacketFilter) error {
	if i.SetFilterFunc == nil {
		return fmt.Errorf("not implemented")
	}
	return i.SetFilterFunc(iface)
}

func TestManagerCreate(t *testing.T) {
	ifaceMock := &IFaceMock{
		SetFilterFunc: func(iface.PacketFilter) error { return nil },
	}

	m, err := Create(ifaceMock)
	if err != nil {
		t.Errorf("failed to create Manager: %v", err)
		return
	}

	if m == nil {
		t.Error("Manager is nil")
	}
}

func TestManagerAddFiltering(t *testing.T) {
	isSetFilterCalled := false
	ifaceMock := &IFaceMock{
		SetFilterFunc: func(iface.PacketFilter) error {
			isSetFilterCalled = true
			return nil
		},
	}

	m, err := Create(ifaceMock)
	if err != nil {
		t.Errorf("failed to create Manager: %v", err)
		return
	}

	ip := net.ParseIP("192.168.1.1")
	proto := fw.ProtocolTCP
	port := &fw.Port{Values: []int{80}}
	direction := fw.RuleDirectionOUT
	action := fw.ActionDrop
	comment := "Test rule"

	rule, err := m.AddFiltering(ip, proto, nil, port, direction, action, comment)
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
		SetFilterFunc: func(iface.PacketFilter) error { return nil },
	}

	m, err := Create(ifaceMock)
	if err != nil {
		t.Errorf("failed to create Manager: %v", err)
		return
	}

	ip := net.ParseIP("192.168.1.1")
	proto := fw.ProtocolTCP
	port := &fw.Port{Values: []int{80}}
	direction := fw.RuleDirectionOUT
	action := fw.ActionDrop
	comment := "Test rule"

	rule, err := m.AddFiltering(ip, proto, nil, port, direction, action, comment)
	if err != nil {
		t.Errorf("failed to add filtering: %v", err)
		return
	}

	ip = net.ParseIP("192.168.1.1")
	proto = fw.ProtocolTCP
	port = &fw.Port{Values: []int{80}}
	direction = fw.RuleDirectionIN
	action = fw.ActionDrop
	comment = "Test rule 2"

	rule2, err := m.AddFiltering(ip, proto, nil, port, direction, action, comment)
	if err != nil {
		t.Errorf("failed to add filtering: %v", err)
		return
	}

	err = m.DeleteRule(rule)
	if err != nil {
		t.Errorf("failed to delete rule: %v", err)
		return
	}

	if idx, ok := m.rulesIndex[rule2.GetRuleID()]; !ok || len(m.incomingRules) != 1 || idx != 0 {
		t.Errorf("rule2 is not in the rulesIndex")
	}

	err = m.DeleteRule(rule2)
	if err != nil {
		t.Errorf("failed to delete rule: %v", err)
		return
	}

	if len(m.rulesIndex) != 0 || len(m.incomingRules) != 0 {
		t.Errorf("rule1 still in the rulesIndex")
	}
}

func TestAddUDPPacketHook(t *testing.T) {
	tests := []struct {
		name       string
		in         bool
		expDir     fw.RuleDirection
		ip         net.IP
		dPort      uint16
		hook       func([]byte) bool
		expectedID string
	}{
		{
			name:   "Test Outgoing UDP Packet Hook",
			in:     false,
			expDir: fw.RuleDirectionOUT,
			ip:     net.IPv4(10, 168, 0, 1),
			dPort:  8000,
			hook:   func([]byte) bool { return true },
		},
		{
			name:   "Test Incoming UDP Packet Hook",
			in:     true,
			expDir: fw.RuleDirectionIN,
			ip:     net.IPv6loopback,
			dPort:  9000,
			hook:   func([]byte) bool { return false },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := &Manager{
				incomingRules: []Rule{},
				outgoingRules: []Rule{},
				rulesIndex:    make(map[string]int),
			}

			manager.AddUDPPacketHook(tt.in, tt.ip, tt.dPort, tt.hook)

			var addedRule Rule
			if tt.in {
				if len(manager.incomingRules) != 1 {
					t.Errorf("expected 1 incoming rule, got %d", len(manager.incomingRules))
					return
				}
				addedRule = manager.incomingRules[0]
			} else {
				if len(manager.outgoingRules) != 1 {
					t.Errorf("expected 1 outgoing rule, got %d", len(manager.outgoingRules))
					return
				}
				addedRule = manager.outgoingRules[0]
			}

			if !tt.ip.Equal(addedRule.ip) {
				t.Errorf("expected ip %s, got %s", tt.ip, addedRule.ip)
				return
			}
			if tt.dPort != addedRule.dPort {
				t.Errorf("expected dPort %d, got %d", tt.dPort, addedRule.dPort)
				return
			}
			if layers.LayerTypeUDP != addedRule.protoLayer {
				t.Errorf("expected protoLayer %s, got %s", layers.LayerTypeUDP, addedRule.protoLayer)
				return
			}
			if tt.expDir != addedRule.direction {
				t.Errorf("expected direction %d, got %d", tt.expDir, addedRule.direction)
				return
			}
			if addedRule.udpHook == nil {
				t.Errorf("expected udpHook to be set")
				return
			}

			// Ensure rulesIndex is correctly updated
			index, ok := manager.rulesIndex[addedRule.id]
			if !ok {
				t.Errorf("expected rule to be in rulesIndex")
				return
			}
			if index != 0 {
				t.Errorf("expected rule index to be 0, got %d", index)
				return
			}
		})
	}
}

func TestManagerReset(t *testing.T) {
	ifaceMock := &IFaceMock{
		SetFilterFunc: func(iface.PacketFilter) error { return nil },
	}

	m, err := Create(ifaceMock)
	if err != nil {
		t.Errorf("failed to create Manager: %v", err)
		return
	}

	ip := net.ParseIP("192.168.1.1")
	proto := fw.ProtocolTCP
	port := &fw.Port{Values: []int{80}}
	direction := fw.RuleDirectionOUT
	action := fw.ActionDrop
	comment := "Test rule"

	_, err = m.AddFiltering(ip, proto, nil, port, direction, action, comment)
	if err != nil {
		t.Errorf("failed to add filtering: %v", err)
		return
	}

	err = m.Reset()
	if err != nil {
		t.Errorf("failed to reset Manager: %v", err)
		return
	}

	if len(m.rulesIndex) != 0 || len(m.outgoingRules) != 0 || len(m.incomingRules) != 0 {
		t.Errorf("rules is not empty")
	}
}

func TestNotMatchByIP(t *testing.T) {
	ifaceMock := &IFaceMock{
		SetFilterFunc: func(iface.PacketFilter) error { return nil },
	}

	m, err := Create(ifaceMock)
	if err != nil {
		t.Errorf("failed to create Manager: %v", err)
		return
	}
	m.wgNetwork = &net.IPNet{
		IP:   net.ParseIP("100.10.0.0"),
		Mask: net.CIDRMask(16, 32),
	}

	ip := net.ParseIP("0.0.0.0")
	proto := fw.ProtocolUDP
	direction := fw.RuleDirectionOUT
	action := fw.ActionAccept
	comment := "Test rule"

	_, err = m.AddFiltering(ip, proto, nil, nil, direction, action, comment)
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
	payload := gopacket.Payload([]byte("test"))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	if err = gopacket.SerializeLayers(buf, opts, ipv4, udp, payload); err != nil {
		t.Errorf("failed to serialize packet: %v", err)
		return
	}

	if m.dropFilter(buf.Bytes(), m.outgoingRules, false) {
		t.Errorf("expected packet to be accepted")
		return
	}

	if err = m.Reset(); err != nil {
		t.Errorf("failed to reset Manager: %v", err)
		return
	}
}

// TestRemovePacketHook tests the functionality of the RemovePacketHook method
func TestRemovePacketHook(t *testing.T) {
	// creating mock iface
	iface := &IFaceMock{
		SetFilterFunc: func(iface.PacketFilter) error { return nil },
	}

	// creating manager instance
	manager, err := Create(iface)
	if err != nil {
		t.Fatalf("Failed to create Manager: %s", err)
	}

	// Add a UDP packet hook
	hookFunc := func(data []byte) bool { return true }
	hookID := manager.AddUDPPacketHook(false, net.IPv4(192, 168, 0, 1), 8080, hookFunc)

	// Assert the hook is added by finding it in the manager's outgoing rules
	found := false
	for _, rule := range manager.outgoingRules {
		if rule.id == hookID {
			found = true
			break
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
	for _, rule := range manager.outgoingRules {
		if rule.id == hookID {
			t.Fatalf("The hook was not removed properly.")
		}
	}
}

func TestUSPFilterCreatePerformance(t *testing.T) {
	for _, testMax := range []int{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000} {
		t.Run(fmt.Sprintf("Testing %d rules", testMax), func(t *testing.T) {
			// just check on the local interface
			ifaceMock := &IFaceMock{
				SetFilterFunc: func(iface.PacketFilter) error { return nil },
			}
			manager, err := Create(ifaceMock)
			require.NoError(t, err)
			time.Sleep(time.Second)

			defer func() {
				if err := manager.Reset(); err != nil {
					t.Errorf("clear the manager state: %v", err)
				}
				time.Sleep(time.Second)
			}()

			ip := net.ParseIP("10.20.0.100")
			start := time.Now()
			for i := 0; i < testMax; i++ {
				port := &fw.Port{Values: []int{1000 + i}}
				if i%2 == 0 {
					_, err = manager.AddFiltering(ip, "tcp", nil, port, fw.RuleDirectionOUT, fw.ActionAccept, "accept HTTP traffic")
				} else {
					_, err = manager.AddFiltering(ip, "tcp", nil, port, fw.RuleDirectionIN, fw.ActionAccept, "accept HTTP traffic")
				}

				require.NoError(t, err, "failed to add rule")
			}
			t.Logf("execution avg per rule: %s", time.Since(start)/time.Duration(testMax))
		})
	}
}
