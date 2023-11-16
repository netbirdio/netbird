//go:build !android

package nftables

import (
	"context"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall"
)

func TestNftablesManager_RestoreOrCreateContainers(t *testing.T) {

	if firewall.Check() != firewall.NFTABLES {
		t.Skip("nftables not supported on this OS")
	}

	manager := newNFTablesManager(context.TODO())

	nftablesTestingClient := &nftables.Conn{}

	defer manager.CleanRoutingRules()

	err := manager.RestoreOrCreateContainers()
	require.NoError(t, err, "shouldn't return error")

	require.Len(t, manager.chains, 2, "should have created chains")
	require.Len(t, manager.rules, 1, "should have created rules")

	pair := firewall.RouterPair{
		ID:          "abc",
		Source:      "100.100.100.1/32",
		Destination: "100.100.100.0/24",
		Masquerade:  true,
	}

	sourceExp := generateCIDRMatcherExpressions("Source", pair.Source)
	destExp := generateCIDRMatcherExpressions("Destination", pair.Destination)

	forward4Exp := append(sourceExp, append(destExp, exprCounterAccept...)...)
	forward4RuleKey := genKey(forwardingFormat, pair.ID)
	inserted4Forwarding := nftablesTestingClient.InsertRule(&nftables.Rule{
		Table:    manager.table,
		Chain:    manager.chains[nftablesRoutingForwardingChain],
		Exprs:    forward4Exp,
		UserData: []byte(forward4RuleKey),
	})

	nat4Exp := append(sourceExp, append(destExp, &expr.Counter{}, &expr.Masq{})...)
	nat4RuleKey := genKey(natFormat, pair.ID)

	inserted4Nat := nftablesTestingClient.InsertRule(&nftables.Rule{
		Table:    manager.table,
		Chain:    manager.chains[nftablesRoutingNatChain],
		Exprs:    nat4Exp,
		UserData: []byte(nat4RuleKey),
	})

	err = nftablesTestingClient.Flush()
	require.NoError(t, err, "shouldn't return error")

	manager.table = nil

	err = manager.RestoreOrCreateContainers()
	require.NoError(t, err, "shouldn't return error")

	require.Len(t, manager.chains, 2, "should have created chains")
	require.Len(t, manager.rules, 3, "should have restored all rules")

	foundRule, found := manager.rules[forward4RuleKey]
	require.True(t, found, "forwarding rule should exist in the map")
	assert.Equal(t, inserted4Forwarding.Exprs, foundRule.Exprs, "stored forwarding rule expressions should match")

	foundRule, found = manager.rules[nat4RuleKey]
	require.True(t, found, "nat rule should exist in the map")
	// match len of output as nftables client doesn't return expressions with Masquerade expression
	assert.ElementsMatch(t, inserted4Nat.Exprs[:len(foundRule.Exprs)], foundRule.Exprs, "stored nat rule expressions should match")
}

func TestNftablesManager_InsertRoutingRules(t *testing.T) {
	if firewall.Check() != firewall.NFTABLES {
		t.Skip("nftables not supported on this OS")
	}

	for _, testCase := range insertRuleTestCases {
		t.Run(testCase.name, func(t *testing.T) {
			manager := newNFTablesManager(context.TODO())

			nftablesTestingClient := &nftables.Conn{}

			defer manager.CleanRoutingRules()

			err := manager.RestoreOrCreateContainers()
			require.NoError(t, err, "shouldn't return error")

			err = manager.InsertRoutingRules(testCase.inputPair)
			require.NoError(t, err, "forwarding pair should be inserted")

			sourceExp := generateCIDRMatcherExpressions("Source", testCase.inputPair.Source)
			destExp := generateCIDRMatcherExpressions("Destination", testCase.inputPair.Destination)
			testingExpression := append(sourceExp, destExp...)
			fwdRuleKey := genKey(forwardingFormat, testCase.inputPair.ID)

			found := 0
			for _, chain := range manager.chains {
				rules, err := nftablesTestingClient.GetRules(chain.Table, chain)
				require.NoError(t, err, "should list rules for %s table and %s chain", chain.Table.Name, chain.Name)
				for _, rule := range rules {
					if len(rule.UserData) > 0 && string(rule.UserData) == fwdRuleKey {
						require.ElementsMatchf(t, rule.Exprs[:len(testingExpression)], testingExpression, "forwarding rule elements should match")
						found = 1
					}
				}
			}

			require.Equal(t, 1, found, "should find at least 1 rule to test")

			if testCase.inputPair.Masquerade {
				natRuleKey := genKey(natFormat, testCase.inputPair.ID)
				found := 0
				for _, chain := range manager.chains {
					rules, err := nftablesTestingClient.GetRules(chain.Table, chain)
					require.NoError(t, err, "should list rules for %s table and %s chain", chain.Table.Name, chain.Name)
					for _, rule := range rules {
						if len(rule.UserData) > 0 && string(rule.UserData) == natRuleKey {
							require.ElementsMatchf(t, rule.Exprs[:len(testingExpression)], testingExpression, "nat rule elements should match")
							found = 1
						}
					}
				}
				require.Equal(t, 1, found, "should find at least 1 rule to test")
			}

			sourceExp = generateCIDRMatcherExpressions("Source", getInPair(testCase.inputPair).Source)
			destExp = generateCIDRMatcherExpressions("Destination", getInPair(testCase.inputPair).Destination)
			testingExpression = append(sourceExp, destExp...)
			inFwdRuleKey := genKey(inForwardingFormat, testCase.inputPair.ID)

			found = 0
			for _, chain := range manager.chains {
				rules, err := nftablesTestingClient.GetRules(chain.Table, chain)
				require.NoError(t, err, "should list rules for %s table and %s chain", chain.Table.Name, chain.Name)
				for _, rule := range rules {
					if len(rule.UserData) > 0 && string(rule.UserData) == inFwdRuleKey {
						require.ElementsMatchf(t, rule.Exprs[:len(testingExpression)], testingExpression, "income forwarding rule elements should match")
						found = 1
					}
				}
			}

			require.Equal(t, 1, found, "should find at least 1 rule to test")

			if testCase.inputPair.Masquerade {
				inNatRuleKey := genKey(inNatFormat, testCase.inputPair.ID)
				found := 0
				for _, chain := range manager.chains {
					rules, err := nftablesTestingClient.GetRules(chain.Table, chain)
					require.NoError(t, err, "should list rules for %s table and %s chain", chain.Table.Name, chain.Name)
					for _, rule := range rules {
						if len(rule.UserData) > 0 && string(rule.UserData) == inNatRuleKey {
							require.ElementsMatchf(t, rule.Exprs[:len(testingExpression)], testingExpression, "income nat rule elements should match")
							found = 1
						}
					}
				}
				require.Equal(t, 1, found, "should find at least 1 rule to test")
			}
		})
	}
}

func TestNftablesManager_RemoveRoutingRules(t *testing.T) {
	if firewall.Check() != firewall.NFTABLES {
		t.Skip("nftables not supported on this OS")
	}

	for _, testCase := range removeRuleTestCases {
		t.Run(testCase.name, func(t *testing.T) {
			manager := newNFTablesManager(context.TODO())

			nftablesTestingClient := &nftables.Conn{}

			defer manager.CleanRoutingRules()

			err := manager.RestoreOrCreateContainers()
			require.NoError(t, err, "shouldn't return error")

			sourceExp := generateCIDRMatcherExpressions("Source", testCase.inputPair.Source)
			destExp := generateCIDRMatcherExpressions("Destination", testCase.inputPair.Destination)

			forwardExp := append(sourceExp, append(destExp, exprCounterAccept...)...)
			forwardRuleKey := genKey(forwardingFormat, testCase.inputPair.ID)
			insertedForwarding := nftablesTestingClient.InsertRule(&nftables.Rule{
				Table:    manager.table,
				Chain:    manager.chains[nftablesRoutingForwardingChain],
				Exprs:    forwardExp,
				UserData: []byte(forwardRuleKey),
			})

			natExp := append(sourceExp, append(destExp, &expr.Counter{}, &expr.Masq{})...)
			natRuleKey := genKey(natFormat, testCase.inputPair.ID)

			insertedNat := nftablesTestingClient.InsertRule(&nftables.Rule{
				Table:    manager.table,
				Chain:    manager.chains[nftablesRoutingNatChain],
				Exprs:    natExp,
				UserData: []byte(natRuleKey),
			})

			sourceExp = generateCIDRMatcherExpressions("Source", getInPair(testCase.inputPair).Source)
			destExp = generateCIDRMatcherExpressions("Destination", getInPair(testCase.inputPair).Destination)

			forwardExp = append(sourceExp, append(destExp, exprCounterAccept...)...)
			inForwardRuleKey := genKey(inForwardingFormat, testCase.inputPair.ID)
			insertedInForwarding := nftablesTestingClient.InsertRule(&nftables.Rule{
				Table:    manager.table,
				Chain:    manager.chains[nftablesRoutingForwardingChain],
				Exprs:    forwardExp,
				UserData: []byte(inForwardRuleKey),
			})

			natExp = append(sourceExp, append(destExp, &expr.Counter{}, &expr.Masq{})...)
			inNatRuleKey := genKey(inNatFormat, testCase.inputPair.ID)

			insertedInNat := nftablesTestingClient.InsertRule(&nftables.Rule{
				Table:    manager.table,
				Chain:    manager.chains[nftablesRoutingNatChain],
				Exprs:    natExp,
				UserData: []byte(inNatRuleKey),
			})

			err = nftablesTestingClient.Flush()
			require.NoError(t, err, "shouldn't return error")

			manager.table = nil

			err = manager.RestoreOrCreateContainers()
			require.NoError(t, err, "shouldn't return error")

			err = manager.RemoveRoutingRules(testCase.inputPair)
			require.NoError(t, err, "shouldn't return error")

			for _, chain := range manager.chains {
				rules, err := nftablesTestingClient.GetRules(chain.Table, chain)
				require.NoError(t, err, "should list rules for %s table and %s chain", chain.Table.Name, chain.Name)
				for _, rule := range rules {
					if len(rule.UserData) > 0 {
						require.NotEqual(t, insertedForwarding.UserData, rule.UserData, "forwarding rule should not exist")
						require.NotEqual(t, insertedNat.UserData, rule.UserData, "nat rule should not exist")
						require.NotEqual(t, insertedInForwarding.UserData, rule.UserData, "income forwarding rule should not exist")
						require.NotEqual(t, insertedInNat.UserData, rule.UserData, "income nat rule should not exist")
					}
				}
			}
		})
	}
}
