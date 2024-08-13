//go:build !android

package iptables

import (
	"context"
	"os/exec"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/test"
)

func isIptablesSupported() bool {
	_, err4 := exec.LookPath("iptables")
	return err4 == nil
}

func TestIptablesManager_RestoreOrCreateContainers(t *testing.T) {
	if !isIptablesSupported() {
		t.SkipNow()
	}

	iptablesClient, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err, "failed to init iptables client")

	manager, err := newRouterManager(context.TODO(), iptablesClient)
	require.NoError(t, err, "should return a valid iptables manager")

	defer func() {
		_ = manager.Reset()
	}()

	require.Len(t, manager.rules, 2, "should have created rules map")

	exists, err := manager.iptablesClient.Exists(tableFilter, chainFORWARD, manager.rules[Ipv4Forwarding]...)
	require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableFilter, chainFORWARD)
	require.True(t, exists, "forwarding rule should exist")

	exists, err = manager.iptablesClient.Exists(tableNat, chainPOSTROUTING, manager.rules[ipv4Nat]...)
	require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableNat, chainPOSTROUTING)
	require.True(t, exists, "postrouting rule should exist")

	pair := firewall.RouterPair{
		ID:          "abc",
		Source:      "100.100.100.1/32",
		Destination: "100.100.100.0/24",
		Masquerade:  true,
	}
	forward4Rule := genRuleSpec(routingFinalForwardJump, pair.Source, pair.Destination)

	err = manager.iptablesClient.Insert(tableFilter, chainRTFWD, 1, forward4Rule...)
	require.NoError(t, err, "inserting rule should not return error")

	nat4Rule := genRuleSpec(routingFinalNatJump, pair.Source, pair.Destination)

	err = manager.iptablesClient.Insert(tableNat, chainRTNAT, 1, nat4Rule...)
	require.NoError(t, err, "inserting rule should not return error")

	err = manager.Reset()
	require.NoError(t, err, "shouldn't return error")
}

func TestIptablesManager_InsertRoutingRules(t *testing.T) {

	if !isIptablesSupported() {
		t.SkipNow()
	}

	for _, testCase := range test.InsertRuleTestCases {
		t.Run(testCase.Name, func(t *testing.T) {
			if testCase.IsV6 {
				t.Skip("Environment does not support IPv6, skipping IPv6 test...")
			}
			iptablesClient, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
			require.NoError(t, err, "failed to init iptables client")

			manager, err := newRouterManager(context.TODO(), iptablesClient)
			require.NoError(t, err, "shouldn't return error")

			defer func() {
				err := manager.Reset()
				if err != nil {
					log.Errorf("failed to reset iptables manager: %s", err)
				}
			}()

			err = manager.InsertRoutingRules(testCase.InputPair)
			require.NoError(t, err, "forwarding pair should be inserted")

			forwardRuleKey := firewall.GenKey(firewall.ForwardingFormat, testCase.InputPair.ID)
			forwardRule := genRuleSpec(routingFinalForwardJump, testCase.InputPair.Source, testCase.InputPair.Destination)

			exists, err := iptablesClient.Exists(tableFilter, chainRTFWD, forwardRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableFilter, chainRTFWD)
			require.True(t, exists, "forwarding rule should exist")

			foundRule, found := manager.rules[forwardRuleKey]
			require.True(t, found, "forwarding rule should exist in the manager map")
			require.Equal(t, forwardRule[:4], foundRule[:4], "stored forwarding rule should match")

			inForwardRuleKey := firewall.GenKey(firewall.InForwardingFormat, testCase.InputPair.ID)
			inForwardRule := genRuleSpec(routingFinalForwardJump, firewall.GetInPair(testCase.InputPair).Source, firewall.GetInPair(testCase.InputPair).Destination)

			exists, err = iptablesClient.Exists(tableFilter, chainRTFWD, inForwardRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableFilter, chainRTFWD)
			require.True(t, exists, "income forwarding rule should exist")

			foundRule, found = manager.rules[inForwardRuleKey]
			require.True(t, found, "income forwarding rule should exist in the manager map")
			require.Equal(t, inForwardRule[:4], foundRule[:4], "stored income forwarding rule should match")

			natRuleKey := firewall.GenKey(firewall.NatFormat, testCase.InputPair.ID)
			natRule := genRuleSpec(routingFinalNatJump, testCase.InputPair.Source, testCase.InputPair.Destination)

			exists, err = iptablesClient.Exists(tableNat, chainRTNAT, natRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableNat, chainRTNAT)
			if testCase.InputPair.Masquerade {
				require.True(t, exists, "nat rule should be created")
				foundNatRule, foundNat := manager.rules[natRuleKey]
				require.True(t, foundNat, "nat rule should exist in the map")
				require.Equal(t, natRule[:4], foundNatRule[:4], "stored nat rule should match")
			} else {
				require.False(t, exists, "nat rule should not be created")
				_, foundNat := manager.rules[natRuleKey]
				require.False(t, foundNat, "nat rule should not exist in the map")
			}

			inNatRuleKey := firewall.GenKey(firewall.InNatFormat, testCase.InputPair.ID)
			inNatRule := genRuleSpec(routingFinalNatJump, firewall.GetInPair(testCase.InputPair).Source, firewall.GetInPair(testCase.InputPair).Destination)

			exists, err = iptablesClient.Exists(tableNat, chainRTNAT, inNatRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableNat, chainRTNAT)
			if testCase.InputPair.Masquerade {
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

	for _, testCase := range test.RemoveRuleTestCases {
		t.Run(testCase.Name, func(t *testing.T) {
			if testCase.IsV6 {
				t.Skip("Environment does not support IPv6, skipping IPv6 test...")
			}
			iptablesClient, _ := iptables.NewWithProtocol(iptables.ProtocolIPv4)

			manager, err := newRouterManager(context.TODO(), iptablesClient)
			require.NoError(t, err, "shouldn't return error")
			defer func() {
				_ = manager.Reset()
			}()

			require.NoError(t, err, "shouldn't return error")

			forwardRuleKey := firewall.GenKey(firewall.ForwardingFormat, testCase.InputPair.ID)
			forwardRule := genRuleSpec(routingFinalForwardJump, testCase.InputPair.Source, testCase.InputPair.Destination)

			err = iptablesClient.Insert(tableFilter, chainRTFWD, 1, forwardRule...)
			require.NoError(t, err, "inserting rule should not return error")

			inForwardRuleKey := firewall.GenKey(firewall.InForwardingFormat, testCase.InputPair.ID)
			inForwardRule := genRuleSpec(routingFinalForwardJump, firewall.GetInPair(testCase.InputPair).Source, firewall.GetInPair(testCase.InputPair).Destination)

			err = iptablesClient.Insert(tableFilter, chainRTFWD, 1, inForwardRule...)
			require.NoError(t, err, "inserting rule should not return error")

			natRuleKey := firewall.GenKey(firewall.NatFormat, testCase.InputPair.ID)
			natRule := genRuleSpec(routingFinalNatJump, testCase.InputPair.Source, testCase.InputPair.Destination)

			err = iptablesClient.Insert(tableNat, chainRTNAT, 1, natRule...)
			require.NoError(t, err, "inserting rule should not return error")

			inNatRuleKey := firewall.GenKey(firewall.InNatFormat, testCase.InputPair.ID)
			inNatRule := genRuleSpec(routingFinalNatJump, firewall.GetInPair(testCase.InputPair).Source, firewall.GetInPair(testCase.InputPair).Destination)

			err = iptablesClient.Insert(tableNat, chainRTNAT, 1, inNatRule...)
			require.NoError(t, err, "inserting rule should not return error")

			err = manager.Reset()
			require.NoError(t, err, "shouldn't return error")

			err = manager.RemoveRoutingRules(testCase.InputPair)
			require.NoError(t, err, "shouldn't return error")

			exists, err := iptablesClient.Exists(tableFilter, chainRTFWD, forwardRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableFilter, chainRTFWD)
			require.False(t, exists, "forwarding rule should not exist")

			_, found := manager.rules[forwardRuleKey]
			require.False(t, found, "forwarding rule should exist in the manager map")

			exists, err = iptablesClient.Exists(tableFilter, chainRTFWD, inForwardRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableFilter, chainRTFWD)
			require.False(t, exists, "income forwarding rule should not exist")

			_, found = manager.rules[inForwardRuleKey]
			require.False(t, found, "income forwarding rule should exist in the manager map")

			exists, err = iptablesClient.Exists(tableNat, chainRTNAT, natRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableNat, chainRTNAT)
			require.False(t, exists, "nat rule should not exist")

			_, found = manager.rules[natRuleKey]
			require.False(t, found, "nat rule should exist in the manager map")

			exists, err = iptablesClient.Exists(tableNat, chainRTNAT, inNatRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableNat, chainRTNAT)
			require.False(t, exists, "income nat rule should not exist")

			_, found = manager.rules[inNatRuleKey]
			require.False(t, found, "income nat rule should exist in the manager map")

		})
	}
}
