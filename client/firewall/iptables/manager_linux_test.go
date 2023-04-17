package iptables

import (
	"net"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall"
)

func TestIptablesManager(t *testing.T) {
	ipv4Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)

	// just check on the local interface
	manager, err := Create("lo")
	require.NoError(t, err)

	var rule1 fw.Rule
	t.Run("add first rule", func(t *testing.T) {
		ip := net.ParseIP("10.20.0.2")
		port := &fw.Port{Values: []int{8080}}
		rule1, err = manager.AddFiltering(ip, "tcp", port, fw.DirectionDst, fw.ActionAccept, "accept HTTP traffic")
		require.NoError(t, err, "failed to add rule")

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
		require.NoError(t, err, "failed to add rule")

		checkRuleSpecs(t, ipv4Client, true, rule2.(*Rule).specs...)
	})

	t.Run("delete first rule", func(t *testing.T) {
		if err := manager.DeleteRule(rule1); err != nil {
			require.NoError(t, err, "failed to delete rule")
		}

		checkRuleSpecs(t, ipv4Client, false, rule1.(*Rule).specs...)
	})

	t.Run("delete second rule", func(t *testing.T) {
		if err := manager.DeleteRule(rule2); err != nil {
			require.NoError(t, err, "failed to delete rule")
		}

		checkRuleSpecs(t, ipv4Client, false, rule2.(*Rule).specs...)
	})

	t.Run("reset check", func(t *testing.T) {
		// add second rule
		ip := net.ParseIP("10.20.0.3")
		port := &fw.Port{Values: []int{5353}}
		_, err = manager.AddFiltering(ip, "udp", port, fw.DirectionDst, fw.ActionAccept, "accept Fake DNS traffic")
		require.NoError(t, err, "failed to add rule")

		err = manager.Reset()
		require.NoError(t, err, "failed to reset")

		ok, err := ipv4Client.ChainExists("filter", ChainFilterName)
		require.NoError(t, err, "failed check chain exists")

		if ok {
			require.NoErrorf(t, err, "chain '%v' still exists after Reset", ChainFilterName)
		}
	})
}

func checkRuleSpecs(t *testing.T, ipv4Client *iptables.IPTables, mustExists bool, rulespec ...string) {
	exists, err := ipv4Client.Exists("filter", ChainFilterName, rulespec...)
	require.NoError(t, err, "failed to check rule")
	require.Falsef(t, !exists && mustExists, "rule '%v' does not exist", rulespec)
	require.Falsef(t, exists && !mustExists, "rule '%v' exist", rulespec)
}
