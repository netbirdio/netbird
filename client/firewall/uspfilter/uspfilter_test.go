package uspfilter

import (
	"fmt"
	"net"
	"testing"

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
	direction := fw.DirectionDst
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
	direction := fw.DirectionDst
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
	direction = fw.DirectionDst
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

	if idx, ok := m.rulesIndex[rule2.GetRuleID()]; !ok || len(m.outputRules) != 1 || idx != 0 {
		t.Errorf("rule2 is not in the rulesIndex")
	}

	err = m.DeleteRule(rule2)
	if err != nil {
		t.Errorf("failed to delete rule: %v", err)
		return
	}

	if len(m.rulesIndex) != 0 || len(m.outputRules) != 0 {
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
	direction := fw.DirectionDst
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

	if len(m.rulesIndex) != 0 || len(m.inputRules) != 0 || len(m.outputRules) != 0 {
		t.Errorf("rules is not empty")
	}
}
