//go:build !android

package iptables

import (
	"context"
	"os/exec"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/require"
)

func isIptablesSupported() bool {
	_, err4 := exec.LookPath("iptables")
	return err4 == nil
}

func TestIptablesManager_RestoreOrCreateContainers(t *testing.T) {

	if !isIptablesSupported() {
		t.SkipNow()
	}

	manager, err := newRouterManager(context.TODO())
	require.NoError(t, err, "should return a valid iptables manager")

	defer manager.CleanRoutingRules()

	err = manager.RestoreOrCreateContainers()
	require.NoError(t, err, "shouldn't return error")

	require.Len(t, manager.rules, 1, "should have created rules map")

	exists, err := manager.iptablesClient.Exists(iptablesFilterTable, iptablesForwardChain, manager.rules[ipv4Forwarding]...)
	require.NoError(t, err, "should be able to query the iptables %s table and %s chain", iptablesFilterTable, iptablesForwardChain)
	require.True(t, exists, "forwarding rule should exist")

	exists, err = manager.iptablesClient.Exists(iptablesNatTable, iptablesPostRoutingChain, manager.rules[ipv4Nat]...)
	require.NoError(t, err, "should be able to query the iptables %s table and %s chain", iptablesNatTable, iptablesPostRoutingChain)
	require.True(t, exists, "postrouting rule should exist")

	pair := router_pair.RouterPair{
		ID:          "abc",
		Source:      "100.100.100.1/32",
		Destination: "100.100.100.0/24",
		Masquerade:  true,
	}
	forward4RuleKey := genKey(forwardingFormat, pair.ID)
	forward4Rule := genRuleSpec(routingFinalForwardJump, forward4RuleKey, pair.Source, pair.Destination)

	err = manager.iptablesClient.Insert(iptablesFilterTable, iptablesRoutingForwardingChain, 1, forward4Rule...)
	require.NoError(t, err, "inserting rule should not return error")

	nat4RuleKey := genKey(natFormat, pair.ID)
	nat4Rule := genRuleSpec(routingFinalNatJump, nat4RuleKey, pair.Source, pair.Destination)

	err = manager.iptablesClient.Insert(iptablesNatTable, iptablesRoutingNatChain, 1, nat4Rule...)
	require.NoError(t, err, "inserting rule should not return error")

	manager.rules = make(map[string][]string)

	err = manager.RestoreOrCreateContainers()
	require.NoError(t, err, "shouldn't return error")

	require.Len(t, manager.rules, 4, "should have restored all rules for ipv4")

	foundRule, found := manager.rules[forward4RuleKey]
	require.True(t, found, "forwarding rule should exist in the map")
	require.Equal(t, forward4Rule[:4], foundRule[:4], "stored forwarding rule should match")

	foundRule, found = manager.rules[nat4RuleKey]
	require.True(t, found, "nat rule should exist in the map")
	require.Equal(t, nat4Rule[:4], foundRule[:4], "stored nat rule should match")
}

func TestIptablesManager_InsertRoutingRules(t *testing.T) {

	if !isIptablesSupported() {
		t.SkipNow()
	}

	for _, testCase := range insertRuleTestCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.TODO())
			iptablesClient, _ := iptables.NewWithProtocol(iptables.ProtocolIPv4)

			manager := &routerManager{
				ctx:            ctx,
				stop:           cancel,
				iptablesClient: iptablesClient,
				rules:          make(map[string][]string),
			}

			defer manager.CleanRoutingRules()

			err := manager.RestoreOrCreateContainers()
			require.NoError(t, err, "shouldn't return error")

			err = manager.InsertRoutingRules(testCase.inputPair)
			require.NoError(t, err, "forwarding pair should be inserted")

			forwardRuleKey := genKey(forwardingFormat, testCase.inputPair.ID)
			forwardRule := genRuleSpec(routingFinalForwardJump, forwardRuleKey, testCase.inputPair.Source, testCase.inputPair.Destination)

			exists, err := iptablesClient.Exists(iptablesFilterTable, iptablesRoutingForwardingChain, forwardRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", iptablesFilterTable, iptablesRoutingForwardingChain)
			require.True(t, exists, "forwarding rule should exist")

			foundRule, found := manager.rules[forwardRuleKey]
			require.True(t, found, "forwarding rule should exist in the manager map")
			require.Equal(t, forwardRule[:4], foundRule[:4], "stored forwarding rule should match")

			inForwardRuleKey := genKey(inForwardingFormat, testCase.inputPair.ID)
			inForwardRule := genRuleSpec(routingFinalForwardJump, inForwardRuleKey, getInPair(testCase.inputPair).Source, getInPair(testCase.inputPair).Destination)

			exists, err = iptablesClient.Exists(iptablesFilterTable, iptablesRoutingForwardingChain, inForwardRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", iptablesFilterTable, iptablesRoutingForwardingChain)
			require.True(t, exists, "income forwarding rule should exist")

			foundRule, found = manager.rules[inForwardRuleKey]
			require.True(t, found, "income forwarding rule should exist in the manager map")
			require.Equal(t, inForwardRule[:4], foundRule[:4], "stored income forwarding rule should match")

			natRuleKey := genKey(natFormat, testCase.inputPair.ID)
			natRule := genRuleSpec(routingFinalNatJump, natRuleKey, testCase.inputPair.Source, testCase.inputPair.Destination)

			exists, err = iptablesClient.Exists(iptablesNatTable, iptablesRoutingNatChain, natRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", iptablesNatTable, iptablesRoutingNatChain)
			if testCase.inputPair.Masquerade {
				require.True(t, exists, "nat rule should be created")
				foundNatRule, foundNat := manager.rules[natRuleKey]
				require.True(t, foundNat, "nat rule should exist in the map")
				require.Equal(t, natRule[:4], foundNatRule[:4], "stored nat rule should match")
			} else {
				require.False(t, exists, "nat rule should not be created")
				_, foundNat := manager.rules[natRuleKey]
				require.False(t, foundNat, "nat rule should not exist in the map")
			}

			inNatRuleKey := genKey(inNatFormat, testCase.inputPair.ID)
			inNatRule := genRuleSpec(routingFinalNatJump, inNatRuleKey, getInPair(testCase.inputPair).Source, getInPair(testCase.inputPair).Destination)

			exists, err = iptablesClient.Exists(iptablesNatTable, iptablesRoutingNatChain, inNatRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", iptablesNatTable, iptablesRoutingNatChain)
			if testCase.inputPair.Masquerade {
				require.True(t, exists, "income nat rule should be created")
				foundNatRule, foundNat := manager.rules[inNatRuleKey]
				require.True(t, foundNat, "income nat rule should exist in the map")
				require.Equal(t, inNatRule[:4], foundNatRule[:4], "stored income nat rule should match")
			} else {
				require.False(t, exists, "nat rule should not be created")
				_, foundNat := manager.rules[inNatRuleKey]
				require.False(t, foundNat, "income nat rule should not exist in the map")
			}
		})
	}
}

func TestIptablesManager_RemoveRoutingRules(t *testing.T) {

	if !isIptablesSupported() {
		t.SkipNow()
	}

	for _, testCase := range removeRuleTestCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.TODO())
			iptablesClient, _ := iptables.NewWithProtocol(iptables.ProtocolIPv4)
			manager := &routerManager{
				ctx:            ctx,
				stop:           cancel,
				iptablesClient: iptablesClient,
				rules:          make(map[string][]string),
			}

			defer manager.CleanRoutingRules()

			err := manager.RestoreOrCreateContainers()
			require.NoError(t, err, "shouldn't return error")

			forwardRuleKey := genKey(forwardingFormat, testCase.inputPair.ID)
			forwardRule := genRuleSpec(routingFinalForwardJump, forwardRuleKey, testCase.inputPair.Source, testCase.inputPair.Destination)

			err = iptablesClient.Insert(iptablesFilterTable, iptablesRoutingForwardingChain, 1, forwardRule...)
			require.NoError(t, err, "inserting rule should not return error")

			inForwardRuleKey := genKey(inForwardingFormat, testCase.inputPair.ID)
			inForwardRule := genRuleSpec(routingFinalForwardJump, inForwardRuleKey, getInPair(testCase.inputPair).Source, getInPair(testCase.inputPair).Destination)

			err = iptablesClient.Insert(iptablesFilterTable, iptablesRoutingForwardingChain, 1, inForwardRule...)
			require.NoError(t, err, "inserting rule should not return error")

			natRuleKey := genKey(natFormat, testCase.inputPair.ID)
			natRule := genRuleSpec(routingFinalNatJump, natRuleKey, testCase.inputPair.Source, testCase.inputPair.Destination)

			err = iptablesClient.Insert(iptablesNatTable, iptablesRoutingNatChain, 1, natRule...)
			require.NoError(t, err, "inserting rule should not return error")

			inNatRuleKey := genKey(inNatFormat, testCase.inputPair.ID)
			inNatRule := genRuleSpec(routingFinalNatJump, inNatRuleKey, getInPair(testCase.inputPair).Source, getInPair(testCase.inputPair).Destination)

			err = iptablesClient.Insert(iptablesNatTable, iptablesRoutingNatChain, 1, inNatRule...)
			require.NoError(t, err, "inserting rule should not return error")

			manager.rules = make(map[string][]string)

			err = manager.RestoreOrCreateContainers()
			require.NoError(t, err, "shouldn't return error")

			err = manager.RemoveRoutingRules(testCase.inputPair)
			require.NoError(t, err, "shouldn't return error")

			exists, err := iptablesClient.Exists(iptablesFilterTable, iptablesRoutingForwardingChain, forwardRule...)
			require.NoError(t, err, "should be able to query the iptables %s %s table and %s chain", testCase.ipVersion, iptablesFilterTable, iptablesRoutingForwardingChain)
			require.False(t, exists, "forwarding rule should not exist")

			_, found := manager.rules[forwardRuleKey]
			require.False(t, found, "forwarding rule should exist in the manager map")

			exists, err = iptablesClient.Exists(iptablesFilterTable, iptablesRoutingForwardingChain, inForwardRule...)
			require.NoError(t, err, "should be able to query the iptables %s %s table and %s chain", testCase.ipVersion, iptablesFilterTable, iptablesRoutingForwardingChain)
			require.False(t, exists, "income forwarding rule should not exist")

			_, found = manager.rules[inForwardRuleKey]
			require.False(t, found, "income forwarding rule should exist in the manager map")

			exists, err = iptablesClient.Exists(iptablesNatTable, iptablesRoutingNatChain, natRule...)
			require.NoError(t, err, "should be able to query the iptables %s %s table and %s chain", testCase.ipVersion, iptablesNatTable, iptablesRoutingNatChain)
			require.False(t, exists, "nat rule should not exist")

			_, found = manager.rules[natRuleKey]
			require.False(t, found, "nat rule should exist in the manager map")

			exists, err = iptablesClient.Exists(iptablesNatTable, iptablesRoutingNatChain, inNatRule...)
			require.NoError(t, err, "should be able to query the iptables %s %s table and %s chain", testCase.ipVersion, iptablesNatTable, iptablesRoutingNatChain)
			require.False(t, exists, "income nat rule should not exist")

			_, found = manager.rules[inNatRuleKey]
			require.False(t, found, "income nat rule should exist in the manager map")

		})
	}
}
