//go:build privileged

package iptables

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
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

		if ok {
			require.NoErrorf(t, err, "chain '%v' still exists after Close", chainACLInput)
		}
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

func checkRuleSpecs(t *testing.T, ipv4Client *iptables.IPTables, chainName string, mustExists bool, rulespec ...string) {
	t.Helper()
	exists, err := ipv4Client.Exists("filter", chainName, rulespec...)
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
