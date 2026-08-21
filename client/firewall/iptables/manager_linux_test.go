//go:build privileged

package iptables

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/lrh3321/ipset-go"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/shared/management/domain"
)

var ifaceMock = &iFaceMock{
	NameFunc: func() string {
		return "wg-test"
	},
	AddressFunc: func() wgaddr.Address {
		return wgaddr.Address{
			IP:      netip.MustParseAddr("10.20.0.1"),
			Network: netip.MustParsePrefix("10.20.0.0/24"),
		}
	},
}

// iFaceMapper defines subset methods of interface required for manager
type iFaceMock struct {
	NameFunc    func() string
	AddressFunc func() wgaddr.Address
}

func (i *iFaceMock) Name() string {
	if i.NameFunc != nil {
		return i.NameFunc()
	}
	panic("NameFunc is not set")
}

func (i *iFaceMock) Address() wgaddr.Address {
	if i.AddressFunc != nil {
		return i.AddressFunc()
	}
	panic("AddressFunc is not set")
}

func TestIptablesManager(t *testing.T) {
	ipv4Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)

	// just check on the local interface
	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	time.Sleep(time.Second)

	defer func() {
		err := manager.Close(nil)
		require.NoError(t, err, "clear the manager state")

		time.Sleep(time.Second)
	}()

	var rule2 fw.Rule
	t.Run("add second rule", func(t *testing.T) {
		ip := netip.MustParseAddr("10.20.0.3")
		port := &fw.Port{
			IsRange: true,
			Values:  []uint16{8043, 8046},
		}
		rule2, err = manager.AddFilterRule(nil, pfx(ip.AsSlice()), fw.Network{}, "tcp", port, nil, fw.ActionAccept)
		require.NoError(t, err, "failed to add rule")

		rr := rule2.(*Rule)
		checkRuleSpecs(t, ipv4Client, rr.chain, true, rr.specs...)
	})

	t.Run("delete second rule", func(t *testing.T) {
		require.NoError(t, manager.DeleteFilterRule(rule2), "failed to delete rule")
	})

	t.Run("reset check", func(t *testing.T) {
		// add second rule
		ip := netip.MustParseAddr("10.20.0.3")
		port := &fw.Port{Values: []uint16{5353}}
		_, err = manager.AddFilterRule(nil, pfx(ip.AsSlice()), fw.Network{}, "udp", nil, port, fw.ActionAccept)
		require.NoError(t, err, "failed to add rule")

		err = manager.Close(nil)
		require.NoError(t, err, "failed to reset")

		ok, err := ipv4Client.ChainExists("filter", chainACLInput)
		require.NoError(t, err, "failed check chain exists")
		require.Falsef(t, ok, "chain %q still exists after Close", chainACLInput)
	})
}

func TestIptablesManagerDenyRules(t *testing.T) {
	ipv4Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)

	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	defer func() {
		err := manager.Close(nil)
		require.NoError(t, err)
	}()

	t.Run("add deny rule", func(t *testing.T) {
		ip := netip.MustParseAddr("10.20.0.3")
		port := &fw.Port{Values: []uint16{22}}

		rule, err := manager.AddFilterRule(nil, pfx(ip.AsSlice()), fw.Network{}, "tcp", nil, port, fw.ActionDrop)
		require.NoError(t, err, "failed to add deny rule")
		require.NotNil(t, rule, "deny rule should not be nil")

		// Verify the rule was added by checking iptables
		rr := rule.(*Rule)
		checkRuleSpecs(t, ipv4Client, rr.chain, true, rr.specs...)
	})

	t.Run("deny rule precedence test", func(t *testing.T) {
		ip := netip.MustParseAddr("10.20.0.4")
		port := &fw.Port{Values: []uint16{80}}

		// Add accept rule first
		_, err := manager.AddFilterRule(nil, pfx(ip.AsSlice()), fw.Network{}, "tcp", nil, port, fw.ActionAccept)
		require.NoError(t, err, "failed to add accept rule")

		// Add deny rule second for same IP/port - this should take precedence
		_, err = manager.AddFilterRule(nil, pfx(ip.AsSlice()), fw.Network{}, "tcp", nil, port, fw.ActionDrop)
		require.NoError(t, err, "failed to add deny rule")

		// Inspect the actual iptables rules to verify deny rule comes before accept rule
		rules, err := ipv4Client.List("filter", chainACLInput)
		require.NoError(t, err, "failed to list iptables rules")

		// Debug: print all rules
		t.Logf("All iptables rules in chain %s:", chainACLInput)
		for i, rule := range rules {
			t.Logf("  [%d] %s", i, rule)
		}

		// Single-source rules emit a direct `-s <ip>/32 ... --dport 80`
		// match. Match on that shape instead of the legacy
		// per-(action,port) ipset names ("deny-http"/"accept-http")
		// that this test predates.
		srcMatch := fmt.Sprintf("-s %s/32", ip)
		var denyRuleIndex, acceptRuleIndex = -1, -1
		for i, rule := range rules {
			if !strings.Contains(rule, srcMatch) || !strings.Contains(rule, "--dport 80") {
				continue
			}
			if strings.Contains(rule, "-j DROP") {
				t.Logf("Found DROP rule at index %d: %s", i, rule)
				denyRuleIndex = i
			}
			if strings.Contains(rule, "-j ACCEPT") {
				t.Logf("Found ACCEPT rule at index %d: %s", i, rule)
				acceptRuleIndex = i
			}
		}

		require.NotEqual(t, -1, denyRuleIndex, "deny rule should exist in iptables")
		require.NotEqual(t, -1, acceptRuleIndex, "accept rule should exist in iptables")
		require.Less(t, denyRuleIndex, acceptRuleIndex,
			"deny rule should come before accept rule in iptables chain (deny at index %d, accept at index %d)",
			denyRuleIndex, acceptRuleIndex)
	})
}

func TestIptablesManagerIPSet(t *testing.T) {
	mock := &iFaceMock{
		NameFunc: func() string {
			return "wg-test"
		},
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("10.20.0.1"),
				Network: netip.MustParsePrefix("10.20.0.0/24"),
			}
		},
	}

	manager, err := Create(mock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	time.Sleep(time.Second)

	defer func() {
		err := manager.Close(nil)
		require.NoError(t, err, "clear the manager state")

		time.Sleep(time.Second)
	}()

	var rule2 fw.Rule
	t.Run("single source uses direct -s match (no ipset)", func(t *testing.T) {
		ip := netip.MustParseAddr("10.20.0.3")
		port := &fw.Port{
			Values: []uint16{443},
		}
		rule2, err = manager.AddFilterRule(nil, pfx(ip.AsSlice()), fw.Network{}, "tcp", port, nil, fw.ActionAccept)
		require.NoError(t, err, "failed to add rule")
		require.NotNil(t, rule2)
		require.Contains(t, rule2.(*Rule).specs, "-s",
			"single-source rule should use direct -s match, not an ipset")
		require.Empty(t, findSets(rule2.(*Rule).specs),
			"single-source rule should not allocate a shared ipset")
	})

	t.Run("delete single-source rule", func(t *testing.T) {
		require.NoError(t, manager.DeleteFilterRule(rule2), "failed to delete rule")
	})

	t.Run("multi-source uses shared ipset", func(t *testing.T) {
		sources := []netip.Prefix{
			netip.PrefixFrom(netip.MustParseAddr("10.20.0.3"), 32),
			netip.PrefixFrom(netip.MustParseAddr("10.20.0.4"), 32),
			netip.PrefixFrom(netip.MustParseAddr("10.20.0.5"), 32),
		}
		port := &fw.Port{Values: []uint16{8080}}
		multi, err := manager.AddFilterRule(nil, sources, fw.Network{}, "tcp", nil, port, fw.ActionAccept)
		require.NoError(t, err, "failed to add multi-source rule")
		require.NotNil(t, multi, "multi-source rule must produce one iptables rule")
		sets := findSets(multi.(*Rule).specs)
		require.Len(t, sets, 1, "multi-source rule must reference exactly one ipset")

		require.NoError(t, manager.DeleteFilterRule(multi))
	})

	t.Run("reset check", func(t *testing.T) {
		err = manager.Close(nil)
		require.NoError(t, err, "failed to reset")
	})
}

// TestIptablesFilterIPSetFallback verifies that when the kernel lacks
// ipset support, a multi-source rule falls back to one iptables rule
// per source prefix instead of silently leaving the chain empty. See
// discussion #6125.
func TestIptablesFilterIPSetFallback(t *testing.T) {
	ipv4Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)

	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	// Simulate a kernel without the ipset hash module.
	manager.family4.ipsetSupported = false

	sources := []netip.Prefix{
		netip.MustParsePrefix("10.20.0.42/32"),
		netip.MustParsePrefix("10.20.0.43/32"),
	}
	port := &fw.Port{Values: []uint16{22}}

	rule, err := manager.AddFilterRule(nil, sources, fw.Network{}, "tcp", nil, port, fw.ActionAccept)
	require.NoError(t, err, "AddFilterRule should succeed via fallback")

	rr := rule.(*Rule)
	all := rr.allSpecs()
	require.Len(t, all, len(sources), "each source prefix needs its own rule")
	for i, fs := range all {
		joined := strings.Join(fs.specs, " ")
		require.Contains(t, joined, "-s "+sources[i].String(), "fallback rule must match by source prefix")
		require.NotContains(t, joined, matchSet, "fallback rule must not use ipset matching")

		// The rule must actually be present in the ACL chain (not silently dropped).
		checkRuleSpecs(t, ipv4Client, rr.chain, true, fs.specs...)

		// Every expanded peer rule keeps its own redirect-mark pairing.
		require.NotNil(t, fs.mangleSpecs, "peer rule must carry a mangle pairing")
		checkTableRuleSpecs(t, ipv4Client, tableMangle, chainRTPre, true, fs.mangleSpecs...)
	}

	require.NoError(t, manager.DeleteFilterRule(rule), "failed to delete fallback rule")
	for _, fs := range all {
		checkRuleSpecs(t, ipv4Client, rr.chain, false, fs.specs...)
		checkTableRuleSpecs(t, ipv4Client, tableMangle, chainRTPre, false, fs.mangleSpecs...)
	}
}

// TestIptablesFilterDestinationSetRequiresIPSet documents that a dynamic
// (domain) destination cannot be expressed without ipset: its prefixes are only
// known after DNS resolution, so there is nothing to expand into per-prefix
// rules. The call must report that rather than install a broader rule than the
// policy allows.
func TestIptablesFilterDestinationSetRequiresIPSet(t *testing.T) {
	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	manager.family4.ipsetSupported = false

	destination := fw.Network{Set: fw.NewDomainSet(domain.List{"example.com"})}

	_, err = manager.AddFilterRule(nil, []netip.Prefix{netip.MustParsePrefix("172.16.0.0/16")},
		destination, fw.ProtocolALL, nil, nil, fw.ActionAccept)
	require.Error(t, err, "a domain destination is not expressible without ipset")
	require.ErrorContains(t, err, "requires ipset")
}

// TestIptablesNatRuleDropsSourceSetOnDestinationFailure covers a marking rule
// whose source set is created but whose destination set is not: the source
// reference has to go back, or the set it created stays in the kernel with a
// count nothing will ever drop.
func TestIptablesNatRuleDropsSourceSetOnDestinationFailure(t *testing.T) {
	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	sourceSet := fw.NewPrefixSet([]netip.Prefix{
		netip.MustParsePrefix("100.0.0.0/16"),
		netip.MustParsePrefix("10.10.0.0/16"),
	})
	destSet := fw.NewDomainSet(domain.List{"example.org"})

	// Poison the destination set's name so its hash:net creation fails after
	// the source set has already been created.
	poisoned := manager.family4.ipsetName(destSet.HashedName())
	require.NoError(t, ipset.Create(poisoned, ipset.TypeHashIP, ipset.CreateOptions{}))
	t.Cleanup(func() {
		if err := ipset.Destroy(poisoned); err != nil {
			t.Logf("destroy poisoned set %s: %v", poisoned, err)
		}
	})

	pair := fw.RouterPair{
		ID:          "nat-source-set-test",
		Source:      fw.Network{Set: sourceSet},
		Destination: fw.Network{Set: destSet},
		Masquerade:  true,
		Dynamic:     true,
	}

	require.Error(t, manager.AddNatRule(pair), "the destination set must fail to be created")

	_, ok := manager.family4.ipsetCounter.Get(manager.family4.ipsetName(sourceSet.HashedName()))
	require.False(t, ok, "the source set reference must be released")
}

// TestIptablesNatRuleReAddKeepsSetReferences re-adds the same NAT rule the way
// a repeated network-map update does. The marking rule's set references must not
// grow, or RemoveNatRule can never drop the count to zero and the set stays in
// the kernel for the rest of the process lifetime.
func TestIptablesNatRuleReAddKeepsSetReferences(t *testing.T) {
	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	set := fw.NewDomainSet(domain.List{"example.com"})
	pair := fw.RouterPair{
		ID:          "nat-reference-test",
		Source:      fw.Network{Prefix: netip.MustParsePrefix("100.0.0.0/16")},
		Destination: fw.Network{Set: set},
		Masquerade:  true,
		Dynamic:     true,
	}

	require.NoError(t, manager.AddNatRule(pair), "add nat rule")
	name := manager.family4.ipsetName(set.HashedName())
	first, ok := manager.family4.ipsetCounter.Get(name)
	require.True(t, ok, "the marking rule must hold a reference to its set")

	require.NoError(t, manager.AddNatRule(pair), "re-add nat rule")
	second, ok := manager.family4.ipsetCounter.Get(name)
	require.True(t, ok, "the set must still be referenced")
	require.Equal(t, first.Count, second.Count, "re-adding the same rule must not add references")

	require.NoError(t, manager.RemoveNatRule(pair), "remove nat rule")
	_, ok = manager.family4.ipsetCounter.Get(name)
	require.False(t, ok, "removing the rule must drop the last reference")
}

// TestIptablesRouteFilterIPSetFallback covers the route ACL side of the
// fallback: with a destination set, the expanded per-source rules land
// in the route forward chain and are all removed on delete.
func TestIptablesRouteFilterIPSetFallback(t *testing.T) {
	ipv4Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)

	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	defer func() {
		require.NoError(t, manager.Close(nil))
	}()

	manager.family4.ipsetSupported = false

	sources := []netip.Prefix{
		netip.MustParsePrefix("172.16.0.0/16"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	destination := fw.Network{Prefix: netip.MustParsePrefix("10.0.0.0/8")}
	port := &fw.Port{Values: []uint16{443}}

	rule, err := manager.AddFilterRule(nil, sources, destination, "tcp", nil, port, fw.ActionAccept)
	require.NoError(t, err, "route ACL must install without ipset")

	rr := rule.(*Rule)
	require.Equal(t, chainRTFwdIn, rr.chain, "route rule must land in the forward chain")

	all := rr.allSpecs()
	require.Len(t, all, len(sources), "each source prefix needs its own rule")
	for i, fs := range all {
		joined := strings.Join(fs.specs, " ")
		require.Contains(t, joined, "-s "+sources[i].String(), "fallback rule must match by source prefix")
		require.NotContains(t, joined, matchSet, "fallback rule must not use ipset matching")
		require.Nil(t, fs.mangleSpecs, "route rules have no mangle pairing")

		checkRuleSpecs(t, ipv4Client, rr.chain, true, fs.specs...)
	}

	require.NoError(t, manager.DeleteFilterRule(rule), "failed to delete fallback rule")
	for _, fs := range all {
		checkRuleSpecs(t, ipv4Client, rr.chain, false, fs.specs...)
	}
}

// TestIptablesCloseRemovesAllState exercises a spread of rule kinds and then
// asserts Close puts every table it touches back exactly as it found it. A
// leaked chain, jump, or ipset survives the daemon and nothing can remove it
// afterwards, since the tracking that knew about it is gone.
func TestIptablesCloseRemovesAllState(t *testing.T) {
	ipv4Client, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	require.NoError(t, err)

	before := snapshotIptables(t, ipv4Client)

	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	// A failed assertion below returns before the Close under test, which would
	// leave this test's chains and sets in the kernel for the next one.
	t.Cleanup(func() {
		if err := manager.Close(nil); err != nil {
			t.Logf("close after failure: %v", err)
		}
	})

	sources := []netip.Prefix{
		netip.MustParsePrefix("10.20.0.42/32"),
		netip.MustParsePrefix("10.20.0.43/32"),
	}

	// A multi-source peer rule: shared ipset plus the mangle redirect pairing.
	_, err = manager.AddFilterRule(nil, sources, fw.Network{}, "tcp",
		nil, &fw.Port{Values: []uint16{22}}, fw.ActionAccept)
	require.NoError(t, err, "add peer rule")

	// A route rule with a dynamic destination: a second set, in the forward chain.
	_, err = manager.AddFilterRule(nil, sources,
		fw.Network{Set: fw.NewDomainSet(domain.List{"example.com"})},
		fw.ProtocolALL, nil, nil, fw.ActionDrop)
	require.NoError(t, err, "add route rule")

	// NAT marking for a routed destination, both directions.
	pair := fw.RouterPair{
		ID:          "cleanup-test",
		Source:      fw.Network{Prefix: netip.MustParsePrefix("100.0.0.0/16")},
		Destination: fw.Network{Prefix: netip.MustParsePrefix("192.168.55.0/24")},
		Masquerade:  true,
	}
	require.NoError(t, manager.AddNatRule(pair), "add nat rule")
	require.NoError(t, manager.EnableRouting(), "enable routing")

	// A DNAT redirect, which also holds a forwarding reference.
	dnat := fw.ForwardRule{
		Protocol:          fw.ProtocolTCP,
		DestinationPort:   fw.Port{Values: []uint16{8080}},
		TranslatedAddress: netip.MustParseAddr("10.20.0.44"),
		TranslatedPort:    fw.Port{Values: []uint16{80}},
	}
	_, err = manager.AddDNATRule(dnat)
	require.NoError(t, err, "add dnat rule")

	require.NotEqual(t, before, snapshotIptables(t, ipv4Client), "the manager must have installed state")

	// Everything above stays in place, so Close is what has to remove it.
	require.NoError(t, manager.Close(nil), "close")

	after := snapshotIptables(t, ipv4Client)
	require.Equal(t, before.chains, after.chains, "Close must remove every chain it created")
	require.Equal(t, before.rules, after.rules, "Close must remove every rule it created")
	require.Equal(t, before.sets, after.sets, "Close must destroy every ipset it created")
}

// iptablesState is a snapshot of the tables the manager writes to, used to
// compare the kernel before and after a manager lifetime.
type iptablesState struct {
	chains map[string][]string
	rules  map[string][]string
	sets   []string
}

func snapshotIptables(t *testing.T, client *iptables.IPTables) iptablesState {
	t.Helper()

	state := iptablesState{
		chains: map[string][]string{},
		rules:  map[string][]string{},
	}

	for _, table := range []string{tableFilter, tableNat, tableMangle, tableRaw} {
		chains, err := client.ListChains(table)
		require.NoErrorf(t, err, "list chains in %s", table)
		slices.Sort(chains)
		state.chains[table] = chains

		for _, chain := range chains {
			rules, err := client.List(table, chain)
			require.NoErrorf(t, err, "list rules in %s/%s", table, chain)
			state.rules[table+"/"+chain] = rules
		}
	}

	sets, err := ipset.ListAll()
	require.NoError(t, err, "list ipsets")
	for _, set := range sets {
		state.sets = append(state.sets, set.SetName)
	}
	slices.Sort(state.sets)

	return state
}

func checkRuleSpecs(t *testing.T, ipv4Client *iptables.IPTables, chainName string, mustExists bool, rulespec ...string) {
	t.Helper()
	checkTableRuleSpecs(t, ipv4Client, tableFilter, chainName, mustExists, rulespec...)
}

func checkTableRuleSpecs(t *testing.T, ipv4Client *iptables.IPTables, table, chainName string, mustExists bool, rulespec ...string) {
	t.Helper()
	exists, err := ipv4Client.Exists(table, chainName, rulespec...)
	require.NoError(t, err, "failed to check rule")
	require.Falsef(t, !exists && mustExists, "rule '%v' does not exist", rulespec)
	require.Falsef(t, exists && !mustExists, "rule '%v' exist", rulespec)
}

func TestIptablesCreatePerformance(t *testing.T) {
	mock := &iFaceMock{
		NameFunc: func() string {
			return "wg-test"
		},
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("10.20.0.1"),
				Network: netip.MustParsePrefix("10.20.0.0/24"),
			}
		},
	}

	for _, testMax := range []int{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000} {
		t.Run(fmt.Sprintf("Testing %d rules", testMax), func(t *testing.T) {
			// just check on the local interface
			manager, err := Create(mock, iface.DefaultMTU)
			require.NoError(t, err)
			require.NoError(t, manager.Init(nil))
			time.Sleep(time.Second)

			defer func() {
				err := manager.Close(nil)
				require.NoError(t, err, "clear the manager state")

				time.Sleep(time.Second)
			}()

			require.NoError(t, err)

			ip := netip.MustParseAddr("10.20.0.100")
			start := time.Now()
			for i := 0; i < testMax; i++ {
				port := &fw.Port{Values: []uint16{uint16(1000 + i)}}
				_, err = manager.AddFilterRule(nil, pfx(ip.AsSlice()), fw.Network{}, "tcp", nil, port, fw.ActionAccept)

				require.NoError(t, err, "failed to add rule")
			}
			t.Logf("execution avg per rule: %s", time.Since(start)/time.Duration(testMax))
		})
	}
}
