//go:build !android

package nftables

import (
	"context"
	"github.com/netbirdio/netbird/iface"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/require"

	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/firewall/test"
)

const (
	// UNKNOWN is the default value for the firewall type for unknown firewall type
	UNKNOWN = iota
	// IPTABLES is the value for the iptables firewall type
	IPTABLES
	// NFTABLES is the value for the nftables firewall type
	NFTABLES
)

func TestNftablesManager_InsertRoutingRules(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this OS")
	}

	table, table6, err := createWorkTables()
	if err != nil {
		t.Fatal(err)
	}

	defer deleteWorkTables()

	for _, testCase := range test.InsertRuleTestCases {
		t.Run(testCase.Name, func(t *testing.T) {
			if testCase.IsV6 && table6 == nil {
				t.Skip("Environment does not support IPv6, skipping IPv6 test...")
			}
			manager, err := newRouter(context.TODO(), table, table6)
			require.NoError(t, err, "failed to create router")

			nftablesTestingClient := &nftables.Conn{}

			defer manager.ResetForwardRules()

			require.NoError(t, err, "shouldn't return error")

			err = manager.InsertRoutingRules(testCase.InputPair)
			defer func() {
				_ = manager.RemoveRoutingRules(testCase.InputPair)
			}()
			require.NoError(t, err, "forwarding pair should be inserted")

			sourceExp := generateCIDRMatcherExpressions(true, testCase.InputPair.Source)
			destExp := generateCIDRMatcherExpressions(false, testCase.InputPair.Destination)
			testingExpression := append(sourceExp, destExp...) //nolint:gocritic
			fwdRuleKey := firewall.GenKey(firewall.ForwardingFormat, testCase.InputPair.ID)

			chains := manager.chains
			if testCase.IsV6 {
				chains = manager.chains6
			}

			found := 0
			for _, chain := range chains {
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

			if testCase.InputPair.Masquerade {
				natRuleKey := firewall.GenKey(firewall.NatFormat, testCase.InputPair.ID)
				found := 0
				for _, chain := range chains {
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

			sourceExp = generateCIDRMatcherExpressions(true, firewall.GetInPair(testCase.InputPair).Source)
			destExp = generateCIDRMatcherExpressions(false, firewall.GetInPair(testCase.InputPair).Destination)
			testingExpression = append(sourceExp, destExp...) //nolint:gocritic
			inFwdRuleKey := firewall.GenKey(firewall.InForwardingFormat, testCase.InputPair.ID)

			found = 0
			for _, chain := range chains {
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

			if testCase.InputPair.Masquerade {
				inNatRuleKey := firewall.GenKey(firewall.InNatFormat, testCase.InputPair.ID)
				found := 0
				for _, chain := range chains {
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
	if check() != NFTABLES {
		t.Skip("nftables not supported on this OS")
	}

	table, table6, err := createWorkTables()
	if err != nil {
		t.Fatal(err)
	}

	defer deleteWorkTables()

	for _, testCase := range test.RemoveRuleTestCases {
		t.Run(testCase.Name, func(t *testing.T) {
			if testCase.IsV6 && table6 == nil {
				t.Skip("Environment does not support IPv6, skipping IPv6 test...")
			}
			manager, err := newRouter(context.TODO(), table, table6)
			require.NoError(t, err, "failed to create router")

			nftablesTestingClient := &nftables.Conn{}

			defer manager.ResetForwardRules()

			sourceExp := generateCIDRMatcherExpressions(true, testCase.InputPair.Source)
			destExp := generateCIDRMatcherExpressions(false, testCase.InputPair.Destination)

			chains := manager.chains
			workTable := table
			if testCase.IsV6 {
				chains = manager.chains6
				workTable = table6
			}

			forwardExp := append(sourceExp, append(destExp, exprCounterAccept...)...) //nolint:gocritic
			forwardRuleKey := firewall.GenKey(firewall.ForwardingFormat, testCase.InputPair.ID)
			insertedForwarding := nftablesTestingClient.InsertRule(&nftables.Rule{
				Table:    workTable,
				Chain:    chains[chainNameRouteingFw],
				Exprs:    forwardExp,
				UserData: []byte(forwardRuleKey),
			})

			natExp := append(sourceExp, append(destExp, &expr.Counter{}, &expr.Masq{})...) //nolint:gocritic
			natRuleKey := firewall.GenKey(firewall.NatFormat, testCase.InputPair.ID)

			insertedNat := nftablesTestingClient.InsertRule(&nftables.Rule{
				Table:    workTable,
				Chain:    chains[chainNameRoutingNat],
				Exprs:    natExp,
				UserData: []byte(natRuleKey),
			})

			sourceExp = generateCIDRMatcherExpressions(true, firewall.GetInPair(testCase.InputPair).Source)
			destExp = generateCIDRMatcherExpressions(false, firewall.GetInPair(testCase.InputPair).Destination)

			forwardExp = append(sourceExp, append(destExp, exprCounterAccept...)...) //nolint:gocritic
			inForwardRuleKey := firewall.GenKey(firewall.InForwardingFormat, testCase.InputPair.ID)
			insertedInForwarding := nftablesTestingClient.InsertRule(&nftables.Rule{
				Table:    workTable,
				Chain:    chains[chainNameRouteingFw],
				Exprs:    forwardExp,
				UserData: []byte(inForwardRuleKey),
			})

			natExp = append(sourceExp, append(destExp, &expr.Counter{}, &expr.Masq{})...) //nolint:gocritic
			inNatRuleKey := firewall.GenKey(firewall.InNatFormat, testCase.InputPair.ID)

			insertedInNat := nftablesTestingClient.InsertRule(&nftables.Rule{
				Table:    workTable,
				Chain:    chains[chainNameRoutingNat],
				Exprs:    natExp,
				UserData: []byte(inNatRuleKey),
			})

			err = nftablesTestingClient.Flush()
			require.NoError(t, err, "shouldn't return error")

			manager.ResetForwardRules()

			err = manager.RemoveRoutingRules(testCase.InputPair)
			require.NoError(t, err, "shouldn't return error")

			for _, chain := range chains {
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

// check returns the firewall type based on common lib checks. It returns UNKNOWN if no firewall is found.
func check() int {
	nf := nftables.Conn{}
	if _, err := nf.ListChains(); err == nil {
		return NFTABLES
	}

	ip, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		return UNKNOWN
	}
	if isIptablesClientAvailable(ip) {
		return IPTABLES
	}

	return UNKNOWN
}

func isIptablesClientAvailable(client *iptables.IPTables) bool {
	_, err := client.ListChains("filter")
	return err == nil
}

func createWorkTables() (*nftables.Table, *nftables.Table, error) {
	sConn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, nil, err
	}

	tables, err := sConn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return nil, nil, err
	}

	tables6, err := sConn.ListTablesOfFamily(nftables.TableFamilyIPv6)
	if err != nil {
		return nil, nil, err
	}

	for _, t := range append(tables, tables6...) {
		if t.Name == tableName {
			sConn.DelTable(t)
		}
	}

	table := sConn.AddTable(&nftables.Table{Name: tableName, Family: nftables.TableFamilyIPv4})
	var table6 *nftables.Table
	if iface.SupportsIPv6() {
		table6 = sConn.AddTable(&nftables.Table{Name: tableName, Family: nftables.TableFamilyIPv6})
	}
	err = sConn.Flush()

	return table, table6, err
}

func deleteWorkTables() {
	sConn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return
	}

	tables, err := sConn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return
	}

	tables6, err := sConn.ListTablesOfFamily(nftables.TableFamilyIPv6)
	if err != nil {
		return
	}
	tables = append(tables, tables6...)

	for _, t := range tables {
		if t.Name == tableName {
			sConn.DelTable(t)
		}
	}
}
