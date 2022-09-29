package routemanager

import (
	"context"
	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestIptablesManager_RestoreOrCreateContainers(t *testing.T) {

	if !isIptablesSupported() {
		t.SkipNow()
	}

	ctx, cancel := context.WithCancel(context.TODO())
	ipv4Client, _ := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	ipv6Client, _ := iptables.NewWithProtocol(iptables.ProtocolIPv6)

	manager := &iptablesManager{
		ctx:        ctx,
		stop:       cancel,
		ipv4Client: ipv4Client,
		ipv6Client: ipv6Client,
		rules:      make(map[string]map[string][]string),
	}

	defer manager.CleanRoutingRules()

	err := manager.RestoreOrCreateContainers()
	require.NoError(t, err, "shouldn't return error")

	require.Len(t, manager.rules, 2, "should have created maps for ipv4 and ipv6")

	require.Len(t, manager.rules[ipv4], 2, "should have created minimal rules for ipv4")

	exists, err := ipv4Client.Exists(iptablesFilterTable, iptablesForwardChain, manager.rules[ipv4][ipv4Forwarding]...)
	require.NoError(t, err, "should be able to query the iptables %s %s table and %s chain", ipv4, iptablesFilterTable, iptablesForwardChain)
	require.True(t, exists, "forwarding rule should exist")

	exists, err = ipv4Client.Exists(iptablesNatTable, iptablesPostRoutingChain, manager.rules[ipv4][ipv4Nat]...)
	require.NoError(t, err, "should be able to query the iptables %s %s table and %s chain", ipv4, iptablesNatTable, iptablesPostRoutingChain)
	require.True(t, exists, "postrouting rule should exist")

	require.Len(t, manager.rules[ipv6], 2, "should have created minimal rules for ipv6")

	exists, err = ipv6Client.Exists(iptablesFilterTable, iptablesForwardChain, manager.rules[ipv6][ipv6Forwarding]...)
	require.NoError(t, err, "should be able to query the iptables %s %s table and %s chain", ipv6, iptablesFilterTable, iptablesForwardChain)
	require.True(t, exists, "forwarding rule should exist")

	exists, err = ipv6Client.Exists(iptablesNatTable, iptablesPostRoutingChain, manager.rules[ipv6][ipv6Nat]...)
	require.NoError(t, err, "should be able to query the iptables %s %s table and %s chain", ipv6, iptablesNatTable, iptablesPostRoutingChain)
	require.True(t, exists, "postrouting rule should exist")

	pair := routerPair{
		ID:          "abc",
		source:      "100.100.100.1/32",
		destination: "100.100.100.0/24",
		masquerade:  true,
	}
	forward4RuleKey := genKey(forwardingFormat, pair.ID)
	forward4Rule := genRuleSpec(routingFinalForwardJump, forward4RuleKey, pair.source, pair.destination)

	err = ipv4Client.Insert(iptablesFilterTable, iptablesRoutingForwardingChain, 1, forward4Rule...)
	require.NoError(t, err, "inserting rule should not return error")

	nat4RuleKey := genKey(natFormat, pair.ID)
	nat4Rule := genRuleSpec(routingFinalNatJump, nat4RuleKey, pair.source, pair.destination)

	err = ipv4Client.Insert(iptablesNatTable, iptablesRoutingNatChain, 1, nat4Rule...)
	require.NoError(t, err, "inserting rule should not return error")

	pair = routerPair{
		ID:          "abc",
		source:      "fc00::1/128",
		destination: "fc11::/64",
		masquerade:  true,
	}

	forward6RuleKey := genKey(forwardingFormat, pair.ID)
	forward6Rule := genRuleSpec(routingFinalForwardJump, forward6RuleKey, pair.source, pair.destination)

	err = ipv6Client.Insert(iptablesFilterTable, iptablesRoutingForwardingChain, 1, forward6Rule...)
	require.NoError(t, err, "inserting rule should not return error")

	nat6RuleKey := genKey(natFormat, pair.ID)
	nat6Rule := genRuleSpec(routingFinalNatJump, nat6RuleKey, pair.source, pair.destination)

	err = ipv6Client.Insert(iptablesNatTable, iptablesRoutingNatChain, 1, nat6Rule...)
	require.NoError(t, err, "inserting rule should not return error")

	delete(manager.rules, ipv4)
	delete(manager.rules, ipv6)

	err = manager.RestoreOrCreateContainers()
	require.NoError(t, err, "shouldn't return error")

	require.Len(t, manager.rules[ipv4], 4, "should have restored all rules for ipv4")

	foundRule, found := manager.rules[ipv4][forward4RuleKey]
	require.True(t, found, "forwarding rule should exist in the map")
	require.Equal(t, forward4Rule[:4], foundRule[:4], "stored forwarding rule should match")

	foundRule, found = manager.rules[ipv4][nat4RuleKey]
	require.True(t, found, "nat rule should exist in the map")
	require.Equal(t, nat4Rule[:4], foundRule[:4], "stored nat rule should match")

	require.Len(t, manager.rules[ipv6], 4, "should have restored all rules for ipv6")

	foundRule, found = manager.rules[ipv6][forward6RuleKey]
	require.True(t, found, "forwarding rule should exist in the map")
	require.Equal(t, forward6Rule[:4], foundRule[:4], "stored forward rule should match")

	foundRule, found = manager.rules[ipv6][nat6RuleKey]
	require.True(t, found, "nat rule should exist in the map")
	require.Equal(t, nat6Rule[:4], foundRule[:4], "stored nat rule should match")
}

func TestIptablesManager_InsertRoutingRules(t *testing.T) {

	if !isIptablesSupported() {
		t.SkipNow()
	}

	for _, testCase := range insertRuleTestCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.TODO())
			ipv4Client, _ := iptables.NewWithProtocol(iptables.ProtocolIPv4)
			ipv6Client, _ := iptables.NewWithProtocol(iptables.ProtocolIPv6)
			iptablesClient := ipv4Client
			if testCase.ipVersion == ipv6 {
				iptablesClient = ipv6Client
			}

			manager := &iptablesManager{
				ctx:        ctx,
				stop:       cancel,
				ipv4Client: ipv4Client,
				ipv6Client: ipv6Client,
				rules:      make(map[string]map[string][]string),
			}

			defer manager.CleanRoutingRules()

			err := manager.RestoreOrCreateContainers()
			require.NoError(t, err, "shouldn't return error")

			err = manager.InsertRoutingRules(testCase.inputPair)
			require.NoError(t, err, "forwarding pair should be inserted")

			forwardRuleKey := genKey(forwardingFormat, testCase.inputPair.ID)
			forwardRule := genRuleSpec(routingFinalForwardJump, forwardRuleKey, testCase.inputPair.source, testCase.inputPair.destination)

			exists, err := iptablesClient.Exists(iptablesFilterTable, iptablesRoutingForwardingChain, forwardRule...)
			require.NoError(t, err, "should be able to query the iptables %s %s table and %s chain", testCase.ipVersion, iptablesFilterTable, iptablesRoutingForwardingChain)
			require.True(t, exists, "forwarding rule should exist")

			foundRule, found := manager.rules[testCase.ipVersion][forwardRuleKey]
			require.True(t, found, "forwarding rule should exist in the manager map")
			require.Equal(t, forwardRule[:4], foundRule[:4], "stored forwarding rule should match")

			inForwardRuleKey := genKey(inForwardingFormat, testCase.inputPair.ID)
			inForwardRule := genRuleSpec(routingFinalForwardJump, inForwardRuleKey, getInPair(testCase.inputPair).source, getInPair(testCase.inputPair).destination)

			exists, err = iptablesClient.Exists(iptablesFilterTable, iptablesRoutingForwardingChain, inForwardRule...)
			require.NoError(t, err, "should be able to query the iptables %s %s table and %s chain", testCase.ipVersion, iptablesFilterTable, iptablesRoutingForwardingChain)
			require.True(t, exists, "income forwarding rule should exist")

			foundRule, found = manager.rules[testCase.ipVersion][inForwardRuleKey]
			require.True(t, found, "income forwarding rule should exist in the manager map")
			require.Equal(t, inForwardRule[:4], foundRule[:4], "stored income forwarding rule should match")

			natRuleKey := genKey(natFormat, testCase.inputPair.ID)
			natRule := genRuleSpec(routingFinalNatJump, natRuleKey, testCase.inputPair.source, testCase.inputPair.destination)

			exists, err = iptablesClient.Exists(iptablesNatTable, iptablesRoutingNatChain, natRule...)
			require.NoError(t, err, "should be able to query the iptables %s %s table and %s chain", testCase.ipVersion, iptablesNatTable, iptablesRoutingNatChain)
			if testCase.inputPair.masquerade {
				require.True(t, exists, "nat rule should be created")
				foundNatRule, foundNat := manager.rules[testCase.ipVersion][natRuleKey]
				require.True(t, foundNat, "nat rule should exist in the map")
				require.Equal(t, natRule[:4], foundNatRule[:4], "stored nat rule should match")
			} else {
				require.False(t, exists, "nat rule should not be created")
				_, foundNat := manager.rules[testCase.ipVersion][natRuleKey]
				require.False(t, foundNat, "nat rule should not exist in the map")
			}

			inNatRuleKey := genKey(natFormat, testCase.inputPair.ID)
			inNatRule := genRuleSpec(routingFinalNatJump, inNatRuleKey, getInPair(testCase.inputPair).source, getInPair(testCase.inputPair).destination)

			exists, err = iptablesClient.Exists(iptablesNatTable, iptablesRoutingNatChain, inNatRule...)
			require.NoError(t, err, "should be able to query the iptables %s %s table and %s chain", testCase.ipVersion, iptablesNatTable, iptablesRoutingNatChain)
			if testCase.inputPair.masquerade {
				require.True(t, exists, "income nat rule should be created")
				foundNatRule, foundNat := manager.rules[testCase.ipVersion][inNatRuleKey]
				require.True(t, foundNat, "income nat rule should exist in the map")
				require.Equal(t, inNatRule[:4], foundNatRule[:4], "stored income nat rule should match")
			} else {
				require.False(t, exists, "nat rule should not be created")
				_, foundNat := manager.rules[testCase.ipVersion][inNatRuleKey]
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
			ipv4Client, _ := iptables.NewWithProtocol(iptables.ProtocolIPv4)
			ipv6Client, _ := iptables.NewWithProtocol(iptables.ProtocolIPv6)
			iptablesClient := ipv4Client
			if testCase.ipVersion == ipv6 {
				iptablesClient = ipv6Client
			}

			manager := &iptablesManager{
				ctx:        ctx,
				stop:       cancel,
				ipv4Client: ipv4Client,
				ipv6Client: ipv6Client,
				rules:      make(map[string]map[string][]string),
			}

			defer manager.CleanRoutingRules()

			err := manager.RestoreOrCreateContainers()
			require.NoError(t, err, "shouldn't return error")

			forwardRuleKey := genKey(forwardingFormat, testCase.inputPair.ID)
			forwardRule := genRuleSpec(routingFinalForwardJump, forwardRuleKey, testCase.inputPair.source, testCase.inputPair.destination)

			err = iptablesClient.Insert(iptablesFilterTable, iptablesRoutingForwardingChain, 1, forwardRule...)
			require.NoError(t, err, "inserting rule should not return error")

			inForwardRuleKey := genKey(inForwardingFormat, testCase.inputPair.ID)
			inForwardRule := genRuleSpec(routingFinalForwardJump, inForwardRuleKey, getInPair(testCase.inputPair).source, getInPair(testCase.inputPair).destination)

			err = iptablesClient.Insert(iptablesFilterTable, iptablesRoutingForwardingChain, 1, inForwardRule...)
			require.NoError(t, err, "inserting rule should not return error")

			natRuleKey := genKey(natFormat, testCase.inputPair.ID)
			natRule := genRuleSpec(routingFinalNatJump, natRuleKey, testCase.inputPair.source, testCase.inputPair.destination)

			err = iptablesClient.Insert(iptablesNatTable, iptablesRoutingNatChain, 1, natRule...)
			require.NoError(t, err, "inserting rule should not return error")

			inNatRuleKey := genKey(inNatFormat, testCase.inputPair.ID)
			inNatRule := genRuleSpec(routingFinalNatJump, inNatRuleKey, getInPair(testCase.inputPair).source, getInPair(testCase.inputPair).destination)

			err = iptablesClient.Insert(iptablesNatTable, iptablesRoutingNatChain, 1, inNatRule...)
			require.NoError(t, err, "inserting rule should not return error")

			delete(manager.rules, ipv4)
			delete(manager.rules, ipv6)

			err = manager.RestoreOrCreateContainers()
			require.NoError(t, err, "shouldn't return error")

			err = manager.RemoveRoutingRules(testCase.inputPair)
			require.NoError(t, err, "shouldn't return error")

			exists, err := iptablesClient.Exists(iptablesFilterTable, iptablesRoutingForwardingChain, forwardRule...)
			require.NoError(t, err, "should be able to query the iptables %s %s table and %s chain", testCase.ipVersion, iptablesFilterTable, iptablesRoutingForwardingChain)
			require.False(t, exists, "forwarding rule should not exist")

			_, found := manager.rules[testCase.ipVersion][forwardRuleKey]
			require.False(t, found, "forwarding rule should exist in the manager map")

			exists, err = iptablesClient.Exists(iptablesFilterTable, iptablesRoutingForwardingChain, inForwardRule...)
			require.NoError(t, err, "should be able to query the iptables %s %s table and %s chain", testCase.ipVersion, iptablesFilterTable, iptablesRoutingForwardingChain)
			require.False(t, exists, "income forwarding rule should not exist")

			_, found = manager.rules[testCase.ipVersion][inForwardRuleKey]
			require.False(t, found, "income forwarding rule should exist in the manager map")

			exists, err = iptablesClient.Exists(iptablesNatTable, iptablesRoutingNatChain, natRule...)
			require.NoError(t, err, "should be able to query the iptables %s %s table and %s chain", testCase.ipVersion, iptablesNatTable, iptablesRoutingNatChain)
			require.False(t, exists, "nat rule should not exist")

			_, found = manager.rules[testCase.ipVersion][natRuleKey]
			require.False(t, found, "nat rule should exist in the manager map")

			exists, err = iptablesClient.Exists(iptablesNatTable, iptablesRoutingNatChain, inNatRule...)
			require.NoError(t, err, "should be able to query the iptables %s %s table and %s chain", testCase.ipVersion, iptablesNatTable, iptablesRoutingNatChain)
			require.False(t, exists, "income nat rule should not exist")

			_, found = manager.rules[testCase.ipVersion][inNatRuleKey]
			require.False(t, found, "income nat rule should exist in the manager map")

		})
	}
}
