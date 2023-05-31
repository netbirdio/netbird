package uspfilter

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/iface"
)

type IFaceMock struct {
	SetFilteringFunc func(iface.PacketFilter) error
}

func (i *IFaceMock) SetFiltering(iface iface.PacketFilter) error {
	if i.SetFilteringFunc == nil {
		return fmt.Errorf("not implemented")
	}
	return i.SetFilteringFunc(iface)
}

func TestManagerCreate(t *testing.T) {
	ifaceMock := &IFaceMock{
		SetFilteringFunc: func(iface.PacketFilter) error { return nil },
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
	isSetFilteringCalled := false
	ifaceMock := &IFaceMock{
		SetFilteringFunc: func(iface.PacketFilter) error {
			isSetFilteringCalled = true
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

	if !isSetFilteringCalled {
		t.Error("SetFiltering was not called")
		return
	}
}

func TestManagerDeleteRule(t *testing.T) {
	ifaceMock := &IFaceMock{
		SetFilteringFunc: func(iface.PacketFilter) error { return nil },
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

func TestManagerReset(t *testing.T) {
	ifaceMock := &IFaceMock{
		SetFilteringFunc: func(iface.PacketFilter) error { return nil },
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

func TestUSPFilterCreatePerformance(t *testing.T) {
	for _, testMax := range []int{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000} {
		t.Run(fmt.Sprintf("Testing %d rules", testMax), func(t *testing.T) {
			// just check on the local interface
			ifaceMock := &IFaceMock{
				SetFilteringFunc: func(iface.PacketFilter) error { return nil },
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
