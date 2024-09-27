//go:build !android

package nftables

import (
	"context"
	"encoding/binary"
	"net/netip"
	"os/exec"
	"testing"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
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

func TestNftablesManager_AddNatRule(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this OS")
	}

	table, err := createWorkTable()
	require.NoError(t, err, "Failed to create work table")

	defer deleteWorkTable()

	for _, testCase := range test.InsertRuleTestCases {
		t.Run(testCase.Name, func(t *testing.T) {
			manager, err := newRouter(context.TODO(), table, ifaceMock)
			require.NoError(t, err, "failed to create router")

			nftablesTestingClient := &nftables.Conn{}

			defer func(manager *router) {
				require.NoError(t, manager.Reset(), "failed to reset rules")
			}(manager)

			require.NoError(t, err, "shouldn't return error")

			err = manager.AddNatRule(testCase.InputPair)
			require.NoError(t, err, "pair should be inserted")

			defer func(manager *router, pair firewall.RouterPair) {
				require.NoError(t, manager.RemoveNatRule(pair), "failed to remove rule")
			}(manager, testCase.InputPair)

			if testCase.InputPair.Masquerade {
				sourceExp := generateCIDRMatcherExpressions(true, testCase.InputPair.Source)
				destExp := generateCIDRMatcherExpressions(false, testCase.InputPair.Destination)
				testingExpression := append(sourceExp, destExp...) //nolint:gocritic
				testingExpression = append(testingExpression,
					&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     ifname(ifaceMock.Name()),
					},
				)

				natRuleKey := firewall.GenKey(firewall.NatFormat, testCase.InputPair)
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

			if testCase.InputPair.Masquerade {
				sourceExp := generateCIDRMatcherExpressions(true, testCase.InputPair.Source)
				destExp := generateCIDRMatcherExpressions(false, testCase.InputPair.Destination)
				testingExpression := append(sourceExp, destExp...) //nolint:gocritic
				testingExpression = append(testingExpression,
					&expr.Meta{Key: expr.MetaKeyOIFNAME, Register: 1},
					&expr.Cmp{
						Op:       expr.CmpOpEq,
						Register: 1,
						Data:     ifname(ifaceMock.Name()),
					},
				)

				inNatRuleKey := firewall.GenKey(firewall.NatFormat, firewall.GetInversePair(testCase.InputPair))
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

func TestNftablesManager_RemoveNatRule(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this OS")
	}

	table, err := createWorkTable()
	require.NoError(t, err, "Failed to create work table")

	defer deleteWorkTable()

	for _, testCase := range test.RemoveRuleTestCases {
		t.Run(testCase.Name, func(t *testing.T) {
			manager, err := newRouter(context.TODO(), table, ifaceMock)
			require.NoError(t, err, "failed to create router")

			nftablesTestingClient := &nftables.Conn{}

			defer func(manager *router) {
				require.NoError(t, manager.Reset(), "failed to reset rules")
			}(manager)

			sourceExp := generateCIDRMatcherExpressions(true, testCase.InputPair.Source)
			destExp := generateCIDRMatcherExpressions(false, testCase.InputPair.Destination)

			natExp := append(sourceExp, append(destExp, &expr.Counter{}, &expr.Masq{})...) //nolint:gocritic
			natRuleKey := firewall.GenKey(firewall.NatFormat, testCase.InputPair)

			insertedNat := nftablesTestingClient.InsertRule(&nftables.Rule{
				Table:    manager.workTable,
				Chain:    manager.chains[chainNameRoutingNat],
				Exprs:    natExp,
				UserData: []byte(natRuleKey),
			})

			sourceExp = generateCIDRMatcherExpressions(true, firewall.GetInversePair(testCase.InputPair).Source)
			destExp = generateCIDRMatcherExpressions(false, firewall.GetInversePair(testCase.InputPair).Destination)

			natExp = append(sourceExp, append(destExp, &expr.Counter{}, &expr.Masq{})...) //nolint:gocritic
			inNatRuleKey := firewall.GenKey(firewall.NatFormat, firewall.GetInversePair(testCase.InputPair))

			insertedInNat := nftablesTestingClient.InsertRule(&nftables.Rule{
				Table:    manager.workTable,
				Chain:    manager.chains[chainNameRoutingNat],
				Exprs:    natExp,
				UserData: []byte(inNatRuleKey),
			})

			err = nftablesTestingClient.Flush()
			require.NoError(t, err, "shouldn't return error")

			err = manager.Reset()
			require.NoError(t, err, "shouldn't return error")

			err = manager.RemoveNatRule(testCase.InputPair)
			require.NoError(t, err, "shouldn't return error")

			for _, chain := range manager.chains {
				rules, err := nftablesTestingClient.GetRules(chain.Table, chain)
				require.NoError(t, err, "should list rules for %s table and %s chain", chain.Table.Name, chain.Name)
				for _, rule := range rules {
					if len(rule.UserData) > 0 {
						require.NotEqual(t, insertedNat.UserData, rule.UserData, "nat rule should not exist")
						require.NotEqual(t, insertedInNat.UserData, rule.UserData, "income nat rule should not exist")
					}
				}
			}
		})
	}
}

func TestRouter_AddRouteFiltering(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}

	workTable, err := createWorkTable()
	require.NoError(t, err, "Failed to create work table")

	defer deleteWorkTable()

	r, err := newRouter(context.Background(), workTable, ifaceMock)
	require.NoError(t, err, "Failed to create router")

	defer func(r *router) {
		require.NoError(t, r.Reset(), "Failed to reset rules")
	}(r)

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

			t.Log("Internal rule expressions:")
			for i, expr := range rule.Exprs {
				t.Logf("  [%d] %T: %+v", i, expr, expr)
			}

			// Verify internal rule content
			verifyRule(t, rule, tt.sources, tt.destination, tt.proto, tt.sPort, tt.dPort, tt.direction, tt.action, tt.expectSet)

			// Check if the rule exists in nftables and verify its content
			rules, err := r.conn.GetRules(r.workTable, r.chains[chainNameRoutingFw])
			require.NoError(t, err, "Failed to get rules from nftables")

			var nftRule *nftables.Rule
			for _, rule := range rules {
				if string(rule.UserData) == ruleKey.GetRuleID() {
					nftRule = rule
					break
				}
			}

			require.NotNil(t, nftRule, "Rule not found in nftables")
			t.Log("Actual nftables rule expressions:")
			for i, expr := range nftRule.Exprs {
				t.Logf("  [%d] %T: %+v", i, expr, expr)
			}

			// Verify actual nftables rule content
			verifyRule(t, nftRule, tt.sources, tt.destination, tt.proto, tt.sPort, tt.dPort, tt.direction, tt.action, tt.expectSet)

			// Clean up
			err = r.DeleteRouteRule(ruleKey)
			require.NoError(t, err, "Failed to delete rule")
		})
	}
}

func TestNftablesCreateIpSet(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}

	workTable, err := createWorkTable()
	require.NoError(t, err, "Failed to create work table")

	defer deleteWorkTable()

	r, err := newRouter(context.Background(), workTable, ifaceMock)
	require.NoError(t, err, "Failed to create router")

	defer func() {
		require.NoError(t, r.Reset(), "Failed to reset router")
	}()

	tests := []struct {
		name     string
		sources  []netip.Prefix
		expected []netip.Prefix
	}{
		{
			name:    "Single IP",
			sources: []netip.Prefix{netip.MustParsePrefix("192.168.1.1/32")},
		},
		{
			name: "Multiple IPs",
			sources: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.1/32"),
				netip.MustParsePrefix("10.0.0.1/32"),
				netip.MustParsePrefix("172.16.0.1/32"),
			},
		},
		{
			name:    "Single Subnet",
			sources: []netip.Prefix{netip.MustParsePrefix("192.168.0.0/24")},
		},
		{
			name: "Multiple Subnets with Various Prefix Lengths",
			sources: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("172.16.0.0/16"),
				netip.MustParsePrefix("192.168.1.0/24"),
				netip.MustParsePrefix("203.0.113.0/26"),
			},
		},
		{
			name: "Mix of Single IPs and Subnets in Different Positions",
			sources: []netip.Prefix{
				netip.MustParsePrefix("192.168.1.1/32"),
				netip.MustParsePrefix("10.0.0.0/16"),
				netip.MustParsePrefix("172.16.0.1/32"),
				netip.MustParsePrefix("203.0.113.0/24"),
			},
		},
		{
			name: "Overlapping IPs/Subnets",
			sources: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("10.0.0.0/16"),
				netip.MustParsePrefix("10.0.0.1/32"),
				netip.MustParsePrefix("192.168.0.0/16"),
				netip.MustParsePrefix("192.168.1.0/24"),
				netip.MustParsePrefix("192.168.1.1/32"),
			},
			expected: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("192.168.0.0/16"),
			},
		},
	}

	// Add this helper function inside TestNftablesCreateIpSet
	printNftSets := func() {
		cmd := exec.Command("nft", "list", "sets")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Logf("Failed to run 'nft list sets': %v", err)
		} else {
			t.Logf("Current nft sets:\n%s", output)
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setName := firewall.GenerateSetName(tt.sources)
			set, err := r.createIpSet(setName, tt.sources)
			if err != nil {
				t.Logf("Failed to create IP set: %v", err)
				printNftSets()
				require.NoError(t, err, "Failed to create IP set")
			}
			require.NotNil(t, set, "Created set is nil")

			// Verify set properties
			assert.Equal(t, setName, set.Name, "Set name mismatch")
			assert.Equal(t, r.workTable, set.Table, "Set table mismatch")
			assert.True(t, set.Interval, "Set interval property should be true")
			assert.Equal(t, nftables.TypeIPAddr, set.KeyType, "Set key type mismatch")

			// Fetch the created set from nftables
			fetchedSet, err := r.conn.GetSetByName(r.workTable, setName)
			require.NoError(t, err, "Failed to fetch created set")
			require.NotNil(t, fetchedSet, "Fetched set is nil")

			// Verify set elements
			elements, err := r.conn.GetSetElements(fetchedSet)
			require.NoError(t, err, "Failed to get set elements")

			// Count the number of unique prefixes (excluding interval end markers)
			uniquePrefixes := make(map[string]bool)
			for _, elem := range elements {
				if !elem.IntervalEnd {
					ip := netip.AddrFrom4(*(*[4]byte)(elem.Key))
					uniquePrefixes[ip.String()] = true
				}
			}

			// Check against expected merged prefixes
			expectedCount := len(tt.expected)
			if expectedCount == 0 {
				expectedCount = len(tt.sources)
			}
			assert.Equal(t, expectedCount, len(uniquePrefixes), "Number of unique prefixes in set doesn't match expected")

			// Verify each expected prefix is in the set
			for _, expected := range tt.expected {
				found := false
				for _, elem := range elements {
					if !elem.IntervalEnd {
						ip := netip.AddrFrom4(*(*[4]byte)(elem.Key))
						if expected.Contains(ip) {
							found = true
							break
						}
					}
				}
				assert.True(t, found, "Expected prefix %s not found in set", expected)
			}

			r.conn.DelSet(set)
			if err := r.conn.Flush(); err != nil {
				t.Logf("Failed to delete set: %v", err)
				printNftSets()
			}
			require.NoError(t, err, "Failed to delete set")
		})
	}
}

func verifyRule(t *testing.T, rule *nftables.Rule, sources []netip.Prefix, destination netip.Prefix, proto firewall.Protocol, sPort, dPort *firewall.Port, direction firewall.RuleDirection, action firewall.Action, expectSet bool) {
	t.Helper()

	assert.NotNil(t, rule, "Rule should not be nil")

	// Verify sources and destination
	if expectSet {
		assert.True(t, containsSetLookup(rule.Exprs), "Rule should contain set lookup for multiple sources")
	} else if len(sources) == 1 && sources[0].Bits() != 0 {
		if direction == firewall.RuleDirectionIN {
			assert.True(t, containsCIDRMatcher(rule.Exprs, sources[0], true), "Rule should contain source CIDR matcher for %s", sources[0])
		} else {
			assert.True(t, containsCIDRMatcher(rule.Exprs, sources[0], false), "Rule should contain destination CIDR matcher for %s", sources[0])
		}
	}

	if direction == firewall.RuleDirectionIN {
		assert.True(t, containsCIDRMatcher(rule.Exprs, destination, false), "Rule should contain destination CIDR matcher for %s", destination)
	} else {
		assert.True(t, containsCIDRMatcher(rule.Exprs, destination, true), "Rule should contain source CIDR matcher for %s", destination)
	}

	// Verify protocol
	if proto != firewall.ProtocolALL {
		assert.True(t, containsProtocol(rule.Exprs, proto), "Rule should contain protocol matcher for %s", proto)
	}

	// Verify ports
	if sPort != nil {
		assert.True(t, containsPort(rule.Exprs, sPort, true), "Rule should contain source port matcher for %v", sPort)
	}
	if dPort != nil {
		assert.True(t, containsPort(rule.Exprs, dPort, false), "Rule should contain destination port matcher for %v", dPort)
	}

	// Verify action
	assert.True(t, containsAction(rule.Exprs, action), "Rule should contain correct action: %s", action)
}

func containsSetLookup(exprs []expr.Any) bool {
	for _, e := range exprs {
		if _, ok := e.(*expr.Lookup); ok {
			return true
		}
	}
	return false
}

func containsCIDRMatcher(exprs []expr.Any, prefix netip.Prefix, isSource bool) bool {
	var offset uint32
	if isSource {
		offset = 12 // src offset
	} else {
		offset = 16 // dst offset
	}

	var payloadFound, bitwiseFound, cmpFound bool
	for _, e := range exprs {
		switch ex := e.(type) {
		case *expr.Payload:
			if ex.Base == expr.PayloadBaseNetworkHeader && ex.Offset == offset && ex.Len == 4 {
				payloadFound = true
			}
		case *expr.Bitwise:
			if ex.Len == 4 && len(ex.Mask) == 4 && len(ex.Xor) == 4 {
				bitwiseFound = true
			}
		case *expr.Cmp:
			if ex.Op == expr.CmpOpEq && len(ex.Data) == 4 {
				cmpFound = true
			}
		}
	}
	return (payloadFound && bitwiseFound && cmpFound) || prefix.Bits() == 0
}

func containsPort(exprs []expr.Any, port *firewall.Port, isSource bool) bool {
	var offset uint32 = 2 // Default offset for destination port
	if isSource {
		offset = 0 // Offset for source port
	}

	var payloadFound, portMatchFound bool
	for _, e := range exprs {
		switch ex := e.(type) {
		case *expr.Payload:
			if ex.Base == expr.PayloadBaseTransportHeader && ex.Offset == offset && ex.Len == 2 {
				payloadFound = true
			}
		case *expr.Cmp:
			if port.IsRange {
				if ex.Op == expr.CmpOpGte || ex.Op == expr.CmpOpLte {
					portMatchFound = true
				}
			} else {
				if ex.Op == expr.CmpOpEq && len(ex.Data) == 2 {
					portValue := binary.BigEndian.Uint16(ex.Data)
					for _, p := range port.Values {
						if uint16(p) == portValue {
							portMatchFound = true
							break
						}
					}
				}
			}
		}
		if payloadFound && portMatchFound {
			return true
		}
	}
	return false
}

func containsProtocol(exprs []expr.Any, proto firewall.Protocol) bool {
	var metaFound, cmpFound bool
	expectedProto, _ := protoToInt(proto)
	for _, e := range exprs {
		switch ex := e.(type) {
		case *expr.Meta:
			if ex.Key == expr.MetaKeyL4PROTO {
				metaFound = true
			}
		case *expr.Cmp:
			if ex.Op == expr.CmpOpEq && len(ex.Data) == 1 && ex.Data[0] == expectedProto {
				cmpFound = true
			}
		}
	}
	return metaFound && cmpFound
}

func containsAction(exprs []expr.Any, action firewall.Action) bool {
	for _, e := range exprs {
		if verdict, ok := e.(*expr.Verdict); ok {
			switch action {
			case firewall.ActionAccept:
				return verdict.Kind == expr.VerdictAccept
			case firewall.ActionDrop:
				return verdict.Kind == expr.VerdictDrop
			}
		}
	}
	return false
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

func createWorkTable() (*nftables.Table, error) {
	sConn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return nil, err
	}

	tables, err := sConn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return nil, err
	}

	for _, t := range tables {
		if t.Name == tableNameNetbird {
			sConn.DelTable(t)
		}
	}

	table := sConn.AddTable(&nftables.Table{Name: tableNameNetbird, Family: nftables.TableFamilyIPv4})
	err = sConn.Flush()

	return table, err
}

func deleteWorkTable() {
	sConn, err := nftables.New(nftables.AsLasting())
	if err != nil {
		return
	}

	tables, err := sConn.ListTablesOfFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return
	}

	for _, t := range tables {
		if t.Name == tableNameNetbird {
			sConn.DelTable(t)
		}
	}
}
