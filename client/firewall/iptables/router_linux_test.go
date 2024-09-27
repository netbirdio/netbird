//go:build !android

package iptables

import (
	"context"
	"net/netip"
	"os/exec"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
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

	manager, err := newRouter(context.TODO(), iptablesClient, ifaceMock)
	require.NoError(t, err, "should return a valid iptables manager")

	defer func() {
		_ = manager.Reset()
	}()

	require.Len(t, manager.rules, 2, "should have created rules map")

	exists, err := manager.iptablesClient.Exists(tableNat, chainPOSTROUTING, manager.rules[ipv4Nat]...)
	require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableNat, chainPOSTROUTING)
	require.True(t, exists, "postrouting rule should exist")

	pair := firewall.RouterPair{
		ID:          "abc",
		Source:      netip.MustParsePrefix("100.100.100.1/32"),
		Destination: netip.MustParsePrefix("100.100.100.0/24"),
		Masquerade:  true,
	}
	forward4Rule := []string{"-s", pair.Source.String(), "-d", pair.Destination.String(), "-j", routingFinalForwardJump}

	err = manager.iptablesClient.Insert(tableFilter, chainRTFWD, 1, forward4Rule...)
	require.NoError(t, err, "inserting rule should not return error")

	nat4Rule := genRuleSpec(routingFinalNatJump, pair.Source, pair.Destination, ifaceMock.Name(), false)

	err = manager.iptablesClient.Insert(tableNat, chainRTNAT, 1, nat4Rule...)
	require.NoError(t, err, "inserting rule should not return error")

	err = manager.Reset()
	require.NoError(t, err, "shouldn't return error")
}

func TestIptablesManager_AddNatRule(t *testing.T) {

	if !isIptablesSupported() {
		t.SkipNow()
	}

	for _, testCase := range test.InsertRuleTestCases {
		t.Run(testCase.Name, func(t *testing.T) {
			iptablesClient, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
			require.NoError(t, err, "failed to init iptables client")

			manager, err := newRouter(context.TODO(), iptablesClient, ifaceMock)
			require.NoError(t, err, "shouldn't return error")

			defer func() {
				err := manager.Reset()
				if err != nil {
					log.Errorf("failed to reset iptables manager: %s", err)
				}
			}()

			err = manager.AddNatRule(testCase.InputPair)
			require.NoError(t, err, "forwarding pair should be inserted")

			natRuleKey := firewall.GenKey(firewall.NatFormat, testCase.InputPair)
			natRule := genRuleSpec(routingFinalNatJump, testCase.InputPair.Source, testCase.InputPair.Destination, ifaceMock.Name(), false)

			exists, err := iptablesClient.Exists(tableNat, chainRTNAT, natRule...)
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

			inNatRuleKey := firewall.GenKey(firewall.NatFormat, firewall.GetInversePair(testCase.InputPair))
			inNatRule := genRuleSpec(routingFinalNatJump, firewall.GetInversePair(testCase.InputPair).Source, firewall.GetInversePair(testCase.InputPair).Destination, ifaceMock.Name(), true)

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

func TestIptablesManager_RemoveNatRule(t *testing.T) {

	if !isIptablesSupported() {
		t.SkipNow()
	}

	for _, testCase := range test.RemoveRuleTestCases {
		t.Run(testCase.Name, func(t *testing.T) {
			iptablesClient, _ := iptables.NewWithProtocol(iptables.ProtocolIPv4)

			manager, err := newRouter(context.TODO(), iptablesClient, ifaceMock)
			require.NoError(t, err, "shouldn't return error")
			defer func() {
				_ = manager.Reset()
			}()

			require.NoError(t, err, "shouldn't return error")

			natRuleKey := firewall.GenKey(firewall.NatFormat, testCase.InputPair)
			natRule := genRuleSpec(routingFinalNatJump, testCase.InputPair.Source, testCase.InputPair.Destination, ifaceMock.Name(), false)

			err = iptablesClient.Insert(tableNat, chainRTNAT, 1, natRule...)
			require.NoError(t, err, "inserting rule should not return error")

			inNatRuleKey := firewall.GenKey(firewall.NatFormat, firewall.GetInversePair(testCase.InputPair))
			inNatRule := genRuleSpec(routingFinalNatJump, firewall.GetInversePair(testCase.InputPair).Source, firewall.GetInversePair(testCase.InputPair).Destination, ifaceMock.Name(), true)

			err = iptablesClient.Insert(tableNat, chainRTNAT, 1, inNatRule...)
			require.NoError(t, err, "inserting rule should not return error")

			err = manager.Reset()
			require.NoError(t, err, "shouldn't return error")

			err = manager.RemoveNatRule(testCase.InputPair)
			require.NoError(t, err, "shouldn't return error")

			exists, err := iptablesClient.Exists(tableNat, chainRTNAT, natRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableNat, chainRTNAT)
			require.False(t, exists, "nat rule should not exist")

			_, found := manager.rules[natRuleKey]
			require.False(t, found, "nat rule should exist in the manager map")

			exists, err = iptablesClient.Exists(tableNat, chainRTNAT, inNatRule...)
			require.NoError(t, err, "should be able to query the iptables %s table and %s chain", tableNat, chainRTNAT)
			require.False(t, exists, "income nat rule should not exist")

			_, found = manager.rules[inNatRuleKey]
			require.False(t, found, "income nat rule should exist in the manager map")
		})
	}
}

func TestRouter_AddRouteFiltering(t *testing.T) {
	if !isIptablesSupported() {
		t.Skip("iptables not supported on this system")
	}

	iptablesClient, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err, "Failed to create iptables client")

	r, err := newRouter(context.Background(), iptablesClient, ifaceMock)
	require.NoError(t, err, "Failed to create router manager")

	defer func() {
		err := r.Reset()
		require.NoError(t, err, "Failed to reset router")
	}()

	tests := []struct {
		name        string
		sources     []netip.Prefix
		destination netip.Prefix
		proto       firewall.Protocol
		sPort       *firewall.Port
		dPort       *firewall.Port
		direction   firewall.RuleDirection
		action      firewall.Action
		expectSet   bool
	}{
		{
			name:        "Basic TCP rule with single source",
			sources:     []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")},
			destination: netip.MustParsePrefix("10.0.0.0/24"),
			proto:       firewall.ProtocolTCP,
			sPort:       nil,
			dPort:       &firewall.Port{Values: []int{80}},
			direction:   firewall.RuleDirectionIN,
			action:      firewall.ActionAccept,
			expectSet:   false,
		},
		{
			name: "UDP rule with multiple sources",
			sources: []netip.Prefix{
				netip.MustParsePrefix("172.16.0.0/16"),
				netip.MustParsePrefix("192.168.0.0/16"),
			},
			destination: netip.MustParsePrefix("10.0.0.0/8"),
			proto:       firewall.ProtocolUDP,
			sPort:       &firewall.Port{Values: []int{1024, 2048}, IsRange: true},
			dPort:       nil,
			direction:   firewall.RuleDirectionOUT,
			action:      firewall.ActionDrop,
			expectSet:   true,
		},
		{
			name:        "All protocols rule",
			sources:     []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			destination: netip.MustParsePrefix("0.0.0.0/0"),
			proto:       firewall.ProtocolALL,
			sPort:       nil,
			dPort:       nil,
			direction:   firewall.RuleDirectionIN,
			action:      firewall.ActionAccept,
			expectSet:   false,
		},
		{
			name:        "ICMP rule",
			sources:     []netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")},
			destination: netip.MustParsePrefix("10.0.0.0/8"),
			proto:       firewall.ProtocolICMP,
			sPort:       nil,
			dPort:       nil,
			direction:   firewall.RuleDirectionIN,
			action:      firewall.ActionAccept,
			expectSet:   false,
		},
		{
			name:        "TCP rule with multiple source ports",
			sources:     []netip.Prefix{netip.MustParsePrefix("172.16.0.0/12")},
			destination: netip.MustParsePrefix("192.168.0.0/16"),
			proto:       firewall.ProtocolTCP,
			sPort:       &firewall.Port{Values: []int{80, 443, 8080}},
			dPort:       nil,
			direction:   firewall.RuleDirectionOUT,
			action:      firewall.ActionAccept,
			expectSet:   false,
		},
		{
			name:        "UDP rule with single IP and port range",
			sources:     []netip.Prefix{netip.MustParsePrefix("192.168.1.1/32")},
			destination: netip.MustParsePrefix("10.0.0.0/24"),
			proto:       firewall.ProtocolUDP,
			sPort:       nil,
			dPort:       &firewall.Port{Values: []int{5000, 5100}, IsRange: true},
			direction:   firewall.RuleDirectionIN,
			action:      firewall.ActionDrop,
			expectSet:   false,
		},
		{
			name:        "TCP rule with source and destination ports",
			sources:     []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
			destination: netip.MustParsePrefix("172.16.0.0/16"),
			proto:       firewall.ProtocolTCP,
			sPort:       &firewall.Port{Values: []int{1024, 65535}, IsRange: true},
			dPort:       &firewall.Port{Values: []int{22}},
			direction:   firewall.RuleDirectionOUT,
			action:      firewall.ActionAccept,
			expectSet:   false,
		},
		{
			name:        "Drop all incoming traffic",
			sources:     []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			destination: netip.MustParsePrefix("192.168.0.0/24"),
			proto:       firewall.ProtocolALL,
			sPort:       nil,
			dPort:       nil,
			direction:   firewall.RuleDirectionIN,
			action:      firewall.ActionDrop,
			expectSet:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleKey, err := r.AddRouteFiltering(tt.sources, tt.destination, tt.proto, tt.sPort, tt.dPort, tt.direction, tt.action)
			require.NoError(t, err, "AddRouteFiltering failed")

			// Check if the rule is in the internal map
			rule, ok := r.rules[ruleKey.GetRuleID()]
			assert.True(t, ok, "Rule not found in internal map")

			// Log the internal rule
			t.Logf("Internal rule: %v", rule)

			// Check if the rule exists in iptables
			exists, err := iptablesClient.Exists(tableFilter, chainRTFWD, rule...)
			assert.NoError(t, err, "Failed to check rule existence")
			assert.True(t, exists, "Rule not found in iptables")

			// Verify rule content
			params := routeFilteringRuleParams{
				Sources:     tt.sources,
				Destination: tt.destination,
				Proto:       tt.proto,
				SPort:       tt.sPort,
				DPort:       tt.dPort,
				Direction:   tt.direction,
				Action:      tt.action,
				SetName:     "",
			}

			expectedRule := genRouteFilteringRuleSpec(params)

			if tt.expectSet {
				setName := firewall.GenerateSetName(tt.sources)
				params.SetName = setName
				expectedRule = genRouteFilteringRuleSpec(params)

				// Check if the set was created
				_, exists := r.ipsetCounter.Get(setName)
				assert.True(t, exists, "IPSet not created")
			}

			assert.Equal(t, expectedRule, rule, "Rule content mismatch")

			// Clean up
			err = r.DeleteRouteRule(ruleKey)
			require.NoError(t, err, "Failed to delete rule")
		})
	}
}
