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

func (i *iFaceMock) IsUserspaceBind() bool { return false }

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

	var rule2 []fw.Rule
	t.Run("add second rule", func(t *testing.T) {
		ip := netip.MustParseAddr("10.20.0.3")
		port := &fw.Port{
			IsRange: true,
			Values:  []uint16{8043, 8046},
		}
		rule2, err = manager.AddPeerFiltering(nil, ip.AsSlice(), "tcp", port, nil, fw.ActionAccept, "")
		require.NoError(t, err, "failed to add rule")

		for _, r := range rule2 {
			rr := r.(*Rule)
			checkRuleSpecs(t, ipv4Client, rr.chain, true, rr.specs...)
		}
	})

	t.Run("delete second rule", func(t *testing.T) {
		for _, r := range rule2 {
			err := manager.DeletePeerRule(r)
			require.NoError(t, err, "failed to delete rule")
		}

		require.Empty(t, manager.aclMgr.ipsetStore.ipsets, "rulesets index after removed second rule must be empty")
	})

	t.Run("reset check", func(t *testing.T) {
		// add second rule
		ip := netip.MustParseAddr("10.20.0.3")
		port := &fw.Port{Values: []uint16{5353}}
		_, err = manager.AddPeerFiltering(nil, ip.AsSlice(), "udp", nil, port, fw.ActionAccept, "")
		require.NoError(t, err, "failed to add rule")

		err = manager.Close(nil)
		require.NoError(t, err, "failed to reset")

		ok, err := ipv4Client.ChainExists("filter", chainNameInputRules)
		require.NoError(t, err, "failed check chain exists")

		if ok {
			require.NoErrorf(t, err, "chain '%v' still exists after Close", chainNameInputRules)
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

		rule, err := manager.AddPeerFiltering(nil, ip.AsSlice(), "tcp", nil, port, fw.ActionDrop, "deny-ssh")
		require.NoError(t, err, "failed to add deny rule")
		require.NotEmpty(t, rule, "deny rule should not be empty")

		// Verify the rule was added by checking iptables
		for _, r := range rule {
			rr := r.(*Rule)
			checkRuleSpecs(t, ipv4Client, rr.chain, true, rr.specs...)
		}
	})

	t.Run("deny rule precedence test", func(t *testing.T) {
		ip := netip.MustParseAddr("10.20.0.4")
		port := &fw.Port{Values: []uint16{80}}

		// Add accept rule first
		_, err := manager.AddPeerFiltering(nil, ip.AsSlice(), "tcp", nil, port, fw.ActionAccept, "accept-http")
		require.NoError(t, err, "failed to add accept rule")

		// Add deny rule second for same IP/port - this should take precedence
		_, err = manager.AddPeerFiltering(nil, ip.AsSlice(), "tcp", nil, port, fw.ActionDrop, "deny-http")
		require.NoError(t, err, "failed to add deny rule")

		// Inspect the actual iptables rules to verify deny rule comes before accept rule
		rules, err := ipv4Client.List("filter", chainNameInputRules)
		require.NoError(t, err, "failed to list iptables rules")

		// Debug: print all rules
		t.Logf("All iptables rules in chain %s:", chainNameInputRules)
		for i, rule := range rules {
			t.Logf("  [%d] %s", i, rule)
		}

		var denyRuleIndex, acceptRuleIndex = -1, -1
		for i, rule := range rules {
			if strings.Contains(rule, "DROP") {
				t.Logf("Found DROP rule at index %d: %s", i, rule)
				if strings.Contains(rule, "deny-http") && strings.Contains(rule, "80") {
					denyRuleIndex = i
				}
			}
			if strings.Contains(rule, "ACCEPT") {
				t.Logf("Found ACCEPT rule at index %d: %s", i, rule)
				if strings.Contains(rule, "accept-http") && strings.Contains(rule, "80") {
					acceptRuleIndex = i
				}
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

	var rule2 []fw.Rule
	t.Run("add second rule", func(t *testing.T) {
		ip := netip.MustParseAddr("10.20.0.3")
		port := &fw.Port{
			Values: []uint16{443},
		}
		rule2, err = manager.AddPeerFiltering(nil, ip.AsSlice(), "tcp", port, nil, fw.ActionAccept, "default")
		for _, r := range rule2 {
			require.NoError(t, err, "failed to add rule")
			require.Equal(t, r.(*Rule).ipsetName, "default-sport", "ipset name must be set")
			require.Equal(t, r.(*Rule).ip, "10.20.0.3", "ipset IP must be set")
		}
	})

	t.Run("delete second rule", func(t *testing.T) {
		for _, r := range rule2 {
			err := manager.DeletePeerRule(r)
			require.NoError(t, err, "failed to delete rule")

			require.Empty(t, manager.aclMgr.ipsetStore.ipsets, "rulesets index after removed second rule must be empty")
		}
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
				_, err = manager.AddPeerFiltering(nil, ip.AsSlice(), "tcp", nil, port, fw.ActionAccept, "")

				require.NoError(t, err, "failed to add rule")
			}
			t.Logf("execution avg per rule: %s", time.Since(start)/time.Duration(testMax))
		})
	}
}
