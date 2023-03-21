package iptables

import (
	"net"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	fw "github.com/netbirdio/netbird/client/firewall"
)

func TestNewManager(t *testing.T) {
	ipv4Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		t.Fatal(err)
	}

	manager, err := Create()
	if err != nil {
		t.Fatal(err)
	}

	var rule1 fw.Rule
	t.Run("add first rule", func(t *testing.T) {
		ip := net.ParseIP("10.20.0.2")
		port := &fw.Port{Values: []int{8080}}
		rule1, err = manager.AddFiltering(ip, "tcp", port, fw.DirectionDst, fw.ActionAccept, "accept HTTP traffic")
		if err != nil {
			t.Errorf("failed to add rule: %v", err)
		}

		checkRuleSpecs(t, ipv4Client, true, rule1.(*Rule).specs...)
	})

	var rule2 fw.Rule
	t.Run("add second rule", func(t *testing.T) {
		ip := net.ParseIP("10.20.0.3")
		port := &fw.Port{
			Values: []int{8043: 8046},
		}
		rule2, err = manager.AddFiltering(
			ip, "tcp", port, fw.DirectionDst, fw.ActionAccept, "accept HTTPS traffic from ports range")
		if err != nil {
			t.Errorf("failed to add rule: %v", err)
		}

		checkRuleSpecs(t, ipv4Client, true, rule2.(*Rule).specs...)
	})

	t.Run("delete first rule", func(t *testing.T) {
		if err := manager.DeleteRule(rule1); err != nil {
			t.Errorf("failed to delete rule: %v", err)
		}

		checkRuleSpecs(t, ipv4Client, false, rule1.(*Rule).specs...)
	})

	t.Run("delete second rule", func(t *testing.T) {
		if err := manager.DeleteRule(rule2); err != nil {
			t.Errorf("failed to delete rule: %v", err)
		}

		checkRuleSpecs(t, ipv4Client, false, rule2.(*Rule).specs...)
	})

	t.Run("reset check", func(t *testing.T) {
		// add second rule
		ip := net.ParseIP("10.20.0.3")
		port := &fw.Port{Values: []int{5353}}
		_, err = manager.AddFiltering(ip, "udp", port, fw.DirectionDst, fw.ActionAccept, "accept Fake DNS traffic")
		if err != nil {
			t.Errorf("failed to add rule: %v", err)
		}

		if err := manager.Reset(); err != nil {
			t.Errorf("failed to reset: %v", err)
		}

		ok, err := ipv4Client.ChainExists("filter", ChainFilterName)
		if err != nil {
			t.Errorf("failed to drop chain: %v", err)
		}

		if ok {
			t.Errorf("chain '%v' still exists after Reset", ChainFilterName)
		}
	})
}

func checkRuleSpecs(t *testing.T, ipv4Client *iptables.IPTables, mustExists bool, rulespec ...string) {
	exists, err := ipv4Client.Exists("filter", ChainFilterName, rulespec...)
	if err != nil {
		t.Errorf("failed to check rule: %v", err)
		return
	}

	if !exists && mustExists {
		t.Errorf("rule '%v' does not exist", rulespec)
		return
	}
	if exists && !mustExists {
		t.Errorf("rule '%v' exist", rulespec)
		return
	}
}
