package ingressgw

import (
	"fmt"
	"net/netip"
	"testing"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
)

var (
	_ firewall.Rule = &MocFwRule{}
	_ DNATFirewall  = &MockDNATFirewall{}
)

type MocFwRule struct {
	id firewall.ForwardRuleID
}

func (m *MocFwRule) GetRuleID() string {
	return string(m.id)
}

type MockDNATFirewall struct {
	errors bool
}

func (m *MockDNATFirewall) AddDNATRule(fwdRule firewall.ForwardRule) (firewall.Rule, error) {
	if m.errors {
		return nil, fmt.Errorf("moc error")
	}

	fwRule := &MocFwRule{
		id: fwdRule.ID(),
	}
	return fwRule, nil
}

func (m *MockDNATFirewall) DeleteDNATRule(rule firewall.Rule) error {
	return nil
}

func (m *MockDNATFirewall) forceError() {
	m.errors = true
}

func TestManager_AddRule(t *testing.T) {
	fw := &MockDNATFirewall{}
	mgr := NewManager(fw)

	port, _ := firewall.NewPort(8080)

	updates := []firewall.ForwardRule{
		{
			Protocol:          firewall.ProtocolTCP,
			DestinationPort:   *port,
			TranslatedAddress: netip.MustParseAddr("172.16.254.1"),
			TranslatedPort:    *port,
		},
		{
			Protocol:          firewall.ProtocolUDP,
			DestinationPort:   *port,
			TranslatedAddress: netip.MustParseAddr("172.16.254.1"),
			TranslatedPort:    *port,
		}}

	if err := mgr.Update(updates); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	rules := mgr.Rules()
	if len(rules) != len(updates) {
		t.Errorf("unexpected rules count: %d", len(rules))
	}
}

func TestManager_UpdateRule(t *testing.T) {
	fw := &MockDNATFirewall{}
	mgr := NewManager(fw)

	port, _ := firewall.NewPort(8080)
	ruleTCP := firewall.ForwardRule{
		Protocol:          firewall.ProtocolTCP,
		DestinationPort:   *port,
		TranslatedAddress: netip.MustParseAddr("172.16.254.1"),
		TranslatedPort:    *port,
	}

	if err := mgr.Update([]firewall.ForwardRule{ruleTCP}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	ruleUDP := firewall.ForwardRule{
		Protocol:          firewall.ProtocolUDP,
		DestinationPort:   *port,
		TranslatedAddress: netip.MustParseAddr("172.16.254.2"),
		TranslatedPort:    *port,
	}

	if err := mgr.Update([]firewall.ForwardRule{ruleUDP}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	rules := mgr.Rules()
	if len(rules) != 1 {
		t.Errorf("unexpected rules count: %d", len(rules))
	}

	if rules[0].TranslatedAddress.String() != ruleUDP.TranslatedAddress.String() {
		t.Errorf("unexpected rule: %v", rules[0])
	}

	if rules[0].TranslatedPort.String() != ruleUDP.TranslatedPort.String() {
		t.Errorf("unexpected rule: %v", rules[0])
	}

	if rules[0].DestinationPort.String() != ruleUDP.DestinationPort.String() {
		t.Errorf("unexpected rule: %v", rules[0])
	}

	if rules[0].Protocol != ruleUDP.Protocol {
		t.Errorf("unexpected rule: %v", rules[0])
	}
}

func TestManager_ExtendRules(t *testing.T) {
	fw := &MockDNATFirewall{}
	mgr := NewManager(fw)

	port, _ := firewall.NewPort(8080)
	ruleTCP := firewall.ForwardRule{
		Protocol:          firewall.ProtocolTCP,
		DestinationPort:   *port,
		TranslatedAddress: netip.MustParseAddr("172.16.254.1"),
		TranslatedPort:    *port,
	}

	ruleUDP := firewall.ForwardRule{
		Protocol:          firewall.ProtocolUDP,
		DestinationPort:   *port,
		TranslatedAddress: netip.MustParseAddr("172.16.254.2"),
		TranslatedPort:    *port,
	}

	if err := mgr.Update([]firewall.ForwardRule{ruleTCP}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if err := mgr.Update([]firewall.ForwardRule{ruleTCP, ruleUDP}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	rules := mgr.Rules()
	if len(rules) != 2 {
		t.Errorf("unexpected rules count: %d", len(rules))
	}
}

func TestManager_Cleanup(t *testing.T) {
	fw := &MockDNATFirewall{}
	mgr := NewManager(fw)

	port, _ := firewall.NewPort(8080)
	ruleTCP := firewall.ForwardRule{
		Protocol:          firewall.ProtocolTCP,
		DestinationPort:   *port,
		TranslatedAddress: netip.MustParseAddr("172.16.254.1"),
		TranslatedPort:    *port,
	}

	if err := mgr.Update([]firewall.ForwardRule{ruleTCP}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if err := mgr.Update([]firewall.ForwardRule{}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	rules := mgr.Rules()
	if len(rules) != 0 {
		t.Errorf("unexpected rules count: %d", len(rules))
	}
}

func TestManager_Close(t *testing.T) {
	fw := &MockDNATFirewall{}
	mgr := NewManager(fw)

	port, _ := firewall.NewPort(8080)
	ruleTCP := firewall.ForwardRule{
		Protocol:          firewall.ProtocolTCP,
		DestinationPort:   *port,
		TranslatedAddress: netip.MustParseAddr("172.16.254.1"),
		TranslatedPort:    *port,
	}

	if err := mgr.Update([]firewall.ForwardRule{ruleTCP}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if err := mgr.Close(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	rules := mgr.Rules()
	if len(rules) != 0 {
		t.Errorf("unexpected rules count: %d", len(rules))
	}
}
