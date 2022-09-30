package routemanager

import (
	"context"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestNftablesManager_RestoreOrCreateContainers(t *testing.T) {

	ctx, cancel := context.WithCancel(context.TODO())

	manager := &nftablesManager{
		ctx:    ctx,
		stop:   cancel,
		conn:   &nftables.Conn{},
		chains: make(map[string]map[string]*nftables.Chain),
		rules:  make(map[string]*nftables.Rule),
	}

	nftablesTestingClient := &nftables.Conn{}

	defer manager.CleanRoutingRules()

	err := manager.RestoreOrCreateContainers()
	require.NoError(t, err, "shouldn't return error")

	require.Len(t, manager.chains, 2, "should have created chains for ipv4 and ipv6")
	require.Len(t, manager.chains[ipv4], 2, "should have created chains for ipv4")
	require.Len(t, manager.chains[ipv4], 2, "should have created chains for ipv6")
	require.Len(t, manager.rules, 2, "should have created rules for ipv4 and ipv6")

	pair := routerPair{
		ID:          "abc",
		source:      "100.100.100.1/32",
		destination: "100.100.100.0/24",
		masquerade:  true,
	}

	sourceExp := generateCIDRMatcherExpressions("source", pair.source)
	destExp := generateCIDRMatcherExpressions("destination", pair.destination)

	forward4Exp := append(sourceExp, append(destExp, exprCounterAccept...)...)
	forward4RuleKey := genKey(forwardingFormat, pair.ID)
	inserted4Forwarding := nftablesTestingClient.InsertRule(&nftables.Rule{
		Table:    manager.tableIPv4,
		Chain:    manager.chains[ipv4][nftablesRoutingForwardingChain],
		Exprs:    forward4Exp,
		UserData: []byte(forward4RuleKey),
	})

	nat4Exp := append(sourceExp, append(destExp, &expr.Counter{}, &expr.Masq{})...)
	nat4RuleKey := genKey(natFormat, pair.ID)

	inserted4Nat := nftablesTestingClient.InsertRule(&nftables.Rule{
		Table:    manager.tableIPv4,
		Chain:    manager.chains[ipv4][nftablesRoutingNatChain],
		Exprs:    nat4Exp,
		UserData: []byte(nat4RuleKey),
	})

	err = nftablesTestingClient.Flush()
	require.NoError(t, err, "shouldn't return error")

	pair = routerPair{
		ID:          "xyz",
		source:      "fc00::1/128",
		destination: "fc11::/64",
		masquerade:  true,
	}

	sourceExp = generateCIDRMatcherExpressions("source", pair.source)
	destExp = generateCIDRMatcherExpressions("destination", pair.destination)

	forward6Exp := append(sourceExp, append(destExp, exprCounterAccept...)...)
	forward6RuleKey := genKey(forwardingFormat, pair.ID)
	inserted6Forwarding := nftablesTestingClient.InsertRule(&nftables.Rule{
		Table:    manager.tableIPv6,
		Chain:    manager.chains[ipv6][nftablesRoutingForwardingChain],
		Exprs:    forward6Exp,
		UserData: []byte(forward6RuleKey),
	})

	nat6Exp := append(sourceExp, append(destExp, &expr.Counter{}, &expr.Masq{})...)
	nat6RuleKey := genKey(natFormat, pair.ID)

	inserted6Nat := nftablesTestingClient.InsertRule(&nftables.Rule{
		Table:    manager.tableIPv6,
		Chain:    manager.chains[ipv6][nftablesRoutingNatChain],
		Exprs:    nat6Exp,
		UserData: []byte(nat6RuleKey),
	})

	err = nftablesTestingClient.Flush()
	require.NoError(t, err, "shouldn't return error")

	manager.tableIPv4 = nil
	manager.tableIPv6 = nil

	err = manager.RestoreOrCreateContainers()
	require.NoError(t, err, "shouldn't return error")

	require.Len(t, manager.chains, 2, "should have created chains for ipv4 and ipv6")
	require.Len(t, manager.chains[ipv4], 2, "should have created chains for ipv4")
	require.Len(t, manager.chains[ipv4], 2, "should have created chains for ipv6")
	require.Len(t, manager.rules, 6, "should have restored all rules for ipv4 and ipv6")

	foundRule, found := manager.rules[forward4RuleKey]
	require.True(t, found, "forwarding rule should exist in the map")
	assert.Equal(t, inserted4Forwarding.Exprs, foundRule.Exprs, "stored forwarding rule expressions should match")

	foundRule, found = manager.rules[nat4RuleKey]
	require.True(t, found, "nat rule should exist in the map")
	// match len of output as nftables client doesn't return expressions with masquerade expression
	assert.ElementsMatch(t, inserted4Nat.Exprs[:len(foundRule.Exprs)], foundRule.Exprs, "stored nat rule expressions should match")

	foundRule, found = manager.rules[forward6RuleKey]
	require.True(t, found, "forwarding rule should exist in the map")
	assert.Equal(t, inserted6Forwarding.Exprs, foundRule.Exprs, "stored forward rule should match")

	foundRule, found = manager.rules[nat6RuleKey]
	require.True(t, found, "nat rule should exist in the map")
	// match len of output as nftables client doesn't return expressions with masquerade expression
	assert.ElementsMatch(t, inserted6Nat.Exprs[:len(foundRule.Exprs)], foundRule.Exprs, "stored nat rule should match")
}

func TestNftablesManager_InsertRoutingRules(t *testing.T) {

	for _, testCase := range insertRuleTestCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.TODO())

			manager := &nftablesManager{
				ctx:    ctx,
				stop:   cancel,
				conn:   &nftables.Conn{},
				chains: make(map[string]map[string]*nftables.Chain),
				rules:  make(map[string]*nftables.Rule),
			}

			nftablesTestingClient := &nftables.Conn{}

			defer manager.CleanRoutingRules()

			err := manager.RestoreOrCreateContainers()
			require.NoError(t, err, "shouldn't return error")

			err = manager.InsertRoutingRules(testCase.inputPair)
			require.NoError(t, err, "forwarding pair should be inserted")

			sourceExp := generateCIDRMatcherExpressions("source", testCase.inputPair.source)
			destExp := generateCIDRMatcherExpressions("destination", testCase.inputPair.destination)
			testingExpression := append(sourceExp, destExp...)
			fwdRuleKey := genKey(forwardingFormat, testCase.inputPair.ID)

			found := 0
			for _, registeredChains := range manager.chains {
				for _, chain := range registeredChains {
					rules, err := nftablesTestingClient.GetRules(chain.Table, chain)
					require.NoError(t, err, "should list rules for %s table and %s chain", chain.Table.Name, chain.Name)
					for _, rule := range rules {
						if len(rule.UserData) > 0 && string(rule.UserData) == fwdRuleKey {
							require.ElementsMatchf(t, rule.Exprs[:len(testingExpression)], testingExpression, "forwarding rule elements should match")
							found = 1
						}
					}
				}
			}

			require.Equal(t, 1, found, "should find at least 1 rule to test")

			if testCase.inputPair.masquerade {
				natRuleKey := genKey(natFormat, testCase.inputPair.ID)
				found := 0
				for _, registeredChains := range manager.chains {
					for _, chain := range registeredChains {
						rules, err := nftablesTestingClient.GetRules(chain.Table, chain)
						require.NoError(t, err, "should list rules for %s table and %s chain", chain.Table.Name, chain.Name)
						for _, rule := range rules {
							if len(rule.UserData) > 0 && string(rule.UserData) == natRuleKey {
								require.ElementsMatchf(t, rule.Exprs[:len(testingExpression)], testingExpression, "nat rule elements should match")
								found = 1
							}
						}
					}
				}
				require.Equal(t, 1, found, "should find at least 1 rule to test")
			}

			sourceExp = generateCIDRMatcherExpressions("source", getInPair(testCase.inputPair).source)
			destExp = generateCIDRMatcherExpressions("destination", getInPair(testCase.inputPair).destination)
			testingExpression = append(sourceExp, destExp...)
			inFwdRuleKey := genKey(inForwardingFormat, testCase.inputPair.ID)

			found = 0
			for _, registeredChains := range manager.chains {
				for _, chain := range registeredChains {
					rules, err := nftablesTestingClient.GetRules(chain.Table, chain)
					require.NoError(t, err, "should list rules for %s table and %s chain", chain.Table.Name, chain.Name)
					for _, rule := range rules {
						if len(rule.UserData) > 0 && string(rule.UserData) == inFwdRuleKey {
							require.ElementsMatchf(t, rule.Exprs[:len(testingExpression)], testingExpression, "income forwarding rule elements should match")
							found = 1
						}
					}
				}
			}

			require.Equal(t, 1, found, "should find at least 1 rule to test")

			if testCase.inputPair.masquerade {
				inNatRuleKey := genKey(inNatFormat, testCase.inputPair.ID)
				found := 0
				for _, registeredChains := range manager.chains {
					for _, chain := range registeredChains {
						rules, err := nftablesTestingClient.GetRules(chain.Table, chain)
						require.NoError(t, err, "should list rules for %s table and %s chain", chain.Table.Name, chain.Name)
						for _, rule := range rules {
							if len(rule.UserData) > 0 && string(rule.UserData) == inNatRuleKey {
								require.ElementsMatchf(t, rule.Exprs[:len(testingExpression)], testingExpression, "income nat rule elements should match")
								found = 1
							}
						}
					}
				}
				require.Equal(t, 1, found, "should find at least 1 rule to test")
			}
		})
	}
}

func TestNftablesManager_RemoveRoutingRules(t *testing.T) {

	for _, testCase := range removeRuleTestCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.TODO())

			manager := &nftablesManager{
				ctx:    ctx,
				stop:   cancel,
				conn:   &nftables.Conn{},
				chains: make(map[string]map[string]*nftables.Chain),
				rules:  make(map[string]*nftables.Rule),
			}

			nftablesTestingClient := &nftables.Conn{}

			defer manager.CleanRoutingRules()

			err := manager.RestoreOrCreateContainers()
			require.NoError(t, err, "shouldn't return error")

			table := manager.tableIPv4
			if testCase.ipVersion == ipv6 {
				table = manager.tableIPv6
			}

			sourceExp := generateCIDRMatcherExpressions("source", testCase.inputPair.source)
			destExp := generateCIDRMatcherExpressions("destination", testCase.inputPair.destination)

			forwardExp := append(sourceExp, append(destExp, exprCounterAccept...)...)
			forwardRuleKey := genKey(forwardingFormat, testCase.inputPair.ID)
			insertedForwarding := nftablesTestingClient.InsertRule(&nftables.Rule{
				Table:    table,
				Chain:    manager.chains[testCase.ipVersion][nftablesRoutingForwardingChain],
				Exprs:    forwardExp,
				UserData: []byte(forwardRuleKey),
			})

			natExp := append(sourceExp, append(destExp, &expr.Counter{}, &expr.Masq{})...)
			natRuleKey := genKey(natFormat, testCase.inputPair.ID)

			insertedNat := nftablesTestingClient.InsertRule(&nftables.Rule{
				Table:    table,
				Chain:    manager.chains[testCase.ipVersion][nftablesRoutingNatChain],
				Exprs:    natExp,
				UserData: []byte(natRuleKey),
			})

			sourceExp = generateCIDRMatcherExpressions("source", getInPair(testCase.inputPair).source)
			destExp = generateCIDRMatcherExpressions("destination", getInPair(testCase.inputPair).destination)

			forwardExp = append(sourceExp, append(destExp, exprCounterAccept...)...)
			inForwardRuleKey := genKey(inForwardingFormat, testCase.inputPair.ID)
			insertedInForwarding := nftablesTestingClient.InsertRule(&nftables.Rule{
				Table:    table,
				Chain:    manager.chains[testCase.ipVersion][nftablesRoutingForwardingChain],
				Exprs:    forwardExp,
				UserData: []byte(inForwardRuleKey),
			})

			natExp = append(sourceExp, append(destExp, &expr.Counter{}, &expr.Masq{})...)
			inNatRuleKey := genKey(inNatFormat, testCase.inputPair.ID)

			insertedInNat := nftablesTestingClient.InsertRule(&nftables.Rule{
				Table:    table,
				Chain:    manager.chains[testCase.ipVersion][nftablesRoutingNatChain],
				Exprs:    natExp,
				UserData: []byte(inNatRuleKey),
			})

			err = nftablesTestingClient.Flush()
			require.NoError(t, err, "shouldn't return error")

			manager.tableIPv4 = nil
			manager.tableIPv6 = nil

			err = manager.RestoreOrCreateContainers()
			require.NoError(t, err, "shouldn't return error")

			err = manager.RemoveRoutingRules(testCase.inputPair)
			require.NoError(t, err, "shouldn't return error")

			for _, registeredChains := range manager.chains {
				for _, chain := range registeredChains {
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
			}
		})
	}
}
