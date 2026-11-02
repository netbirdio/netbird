//go:build privileged

package nftables

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall/fwtest"
	firewall "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/statemanager"
)

func hasIPv6Table(t *testing.T) bool {
	t.Helper()
	return ip6TableExists(t, getTableName())
}

func ip6TableExists(t *testing.T, name string) bool {
	t.Helper()

	tables, err := (&nftables.Conn{}).ListTablesOfFamily(nftables.TableFamilyIPv6)
	require.NoError(t, err, "list ip6 tables")
	for _, table := range tables {
		if table.Name == name {
			return true
		}
	}
	return false
}

func overlayOnlyV4(ifaceName string) *iFaceMock {
	return &iFaceMock{
		NameFunc: func() string { return ifaceName },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.96.0.1"),
				Network: netip.MustParsePrefix("100.96.0.0/16"),
			}
		},
	}
}

// An interface without an IPv6 overlay address still receives IPv6 from its peers, since a
// peer chooses the source addresses it is allowed. With no IPv6 rules to accept it, all of it
// must be dropped, and removing the firewall must give the interface back.
func TestNftablesManagerDropsIPv6WithoutOverlayAddress(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}
	if !firewall.HostHasIPv6("nb-test0") {
		t.Skip("host has no IPv6")
	}
	if err := probeIPv6Filtering(); err != nil {
		t.Skipf("nftables cannot filter IPv6: %v", err)
	}

	ns := fwtest.NewPeerNamespace(t)
	addr := ns.ListenHost(t)

	ns.WaitDial(t, addr, "control: connection without the firewall")

	manager, err := Create(overlayOnlyV4(ns.IfaceName), iface.DefaultMTU)
	require.NoError(t, err, "create manager")
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = manager.Close(nil)
		}
	})
	require.NoError(t, manager.Init(nil))

	assert.True(t, hasIPv6Table(t), "the ip6 table must exist while the firewall runs")
	assert.Error(t, ns.Dial(addr), "IPv6 arriving on an interface without an IPv6 overlay address must be dropped")

	require.NoError(t, manager.Close(nil))
	closed = true

	assert.False(t, hasIPv6Table(t), "Close must remove the ip6 table")
	ns.WaitDial(t, addr, "connection must work again once the firewall is closed")
}

// countAcceptRules returns how many of the accept rules NetBird puts into host chains are in
// the chains of the given table.
func countAcceptRules(t *testing.T, family nftables.TableFamily, tableName string) int {
	t.Helper()

	conn := &nftables.Conn{}
	chains, err := conn.ListChainsOfTableFamily(family)
	require.NoError(t, err, "list ip6 chains")

	count := 0
	for _, chain := range chains {
		if chain.Table.Name != tableName {
			continue
		}
		rules, err := conn.GetRules(chain.Table, chain)
		require.NoError(t, err, "get rules of %s/%s", chain.Table.Name, chain.Name)
		for _, rule := range rules {
			if string(rule.UserData) == userDataAcceptInputRule {
				count++
			}
		}
	}
	return count
}

// After a crash the saved state is what removes the firewall. Everything the IPv6 deny put in
// place has to go: its table, and the accept rule it added to a chain of the host. That holds
// even if the host looks different when the cleanup runs than it did when the firewall started.
func TestNftablesManagerCrashCleanupRemovesIPv6Deny(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}
	if !firewall.HostHasIPv6("nb-test0") {
		t.Skip("host has no IPv6")
	}
	if err := probeIPv6Filtering(); err != nil {
		t.Skipf("nftables cannot filter IPv6: %v", err)
	}

	ns := fwtest.NewPeerNamespace(t)
	addr := ns.ListenHost(t)

	// A table of the host, with an input chain NetBird adds its accept rule to.
	const hostTable = "nbtest-hostfw"
	host := &nftables.Conn{}
	table := host.AddTable(&nftables.Table{Name: hostTable, Family: nftables.TableFamilyIPv6})
	host.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
	})
	// What an interrupted probe leaves behind.
	strayName := probeTablePrefix + "deadbeef"
	stray := host.AddTable(&nftables.Table{Name: strayName, Family: nftables.TableFamilyIPv6})
	require.NoError(t, host.Flush(), "create host tables")
	t.Cleanup(func() {
		// One table per flush: a table that is already gone fails the whole batch.
		for _, tbl := range []*nftables.Table{table, stray} {
			c := &nftables.Conn{}
			c.DelTable(tbl)
			_ = c.Flush()
		}
	})

	ns.WaitDial(t, addr, "control: connection without the firewall")

	statePath := filepath.Join(t.TempDir(), "state.json")
	sm := statemanager.New(statePath)

	manager, err := Create(overlayOnlyV4(ns.IfaceName), iface.DefaultMTU)
	require.NoError(t, err, "create manager")
	// Stops the monitor of the manager that "crashed", and does nothing else once the cleanup ran.
	t.Cleanup(func() { _ = manager.Close(nil) })
	require.NoError(t, manager.Init(sm))
	require.NoError(t, sm.PersistState(context.Background()), "persist state")

	require.True(t, hasIPv6Table(t), "the ip6 table must exist while the firewall runs")
	require.Equal(t, 1, countAcceptRules(t, nftables.TableFamilyIPv6, hostTable), "the accept rule must be in the host chain while the firewall runs")
	require.Error(t, ns.Dial(addr), "IPv6 must be dropped while the firewall runs")

	// The process is gone without closing the firewall. The new run finds the saved state and
	// cleans up, and the host has no IPv6 by then.
	hostHasIPv6 = func(string) bool { return false }
	t.Cleanup(func() { hostHasIPv6 = firewall.HostHasIPv6 })

	recovered := statemanager.New(statePath)
	recovered.RegisterState(&ShutdownState{})
	require.NoError(t, recovered.PerformCleanup(), "crash cleanup")

	assert.False(t, hasIPv6Table(t), "crash cleanup must remove the ip6 table")
	assert.False(t, ip6TableExists(t, strayName), "crash cleanup must remove a probe table that was left behind")
	assert.Equal(t, 0, countAcceptRules(t, nftables.TableFamilyIPv6, hostTable), "crash cleanup must remove the accept rule from the host chain")
	ns.WaitDial(t, addr, "connection must work again after the crash cleanup")

	require.NoError(t, recovered.PersistState(context.Background()))
	names, err := recovered.GetSavedStateNames()
	require.NoError(t, err)
	assert.NotContains(t, names, (&ShutdownState{}).Name(), "the state must be deleted once the cleanup succeeded")
}

// A host without an IPv6 overlay address on the interface and IPv6 enabled gets the deny, and
// an interface with an overlay address keeps its table and rules as before.
func TestNftablesManagerIPv6FamilyFollowsHostAndOverlay(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}

	withV6 := &iFaceMock{
		NameFunc: func() string { return "wt-fam" },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.96.0.1"),
				Network: netip.MustParsePrefix("100.96.0.0/16"),
				IPv6:    netip.MustParseAddr("fd00::1"),
				IPv6Net: netip.MustParsePrefix("fd00::/64"),
			}
		},
	}
	m, err := Create(withV6, iface.DefaultMTU)
	require.NoError(t, err)
	assert.True(t, m.hasIPv6(), "an IPv6 overlay address means IPv6 rules apply")
	assert.True(t, m.hasV6Family())

	m, err = Create(overlayOnlyV4("wt-fam"), iface.DefaultMTU)
	require.NoError(t, err)
	assert.False(t, m.hasIPv6(), "no IPv6 overlay address means no IPv6 rules, NAT or forwarding")
	wantFamily := hostHasIPv6("wt-fam") && probeIPv6Filtering() == nil
	assert.Equal(t, wantFamily, m.hasV6Family(), "the deny exists when the host has IPv6 and nftables can filter it")

	_, err = m.AddFilterRule(nil, []netip.Prefix{netip.MustParsePrefix("fd00::2/128")}, firewall.Network{}, firewall.ProtocolALL, nil, nil, firewall.ActionAccept)
	assert.ErrorIs(t, err, firewall.ErrIPv6NotInitialized, "IPv6 rules are still refused without an overlay address")
}

// The escape hatch leaves IPv6 on an interface without an IPv6 overlay address to the host.
func TestNftablesManagerAllowUnfilteredIPv6(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}
	if !firewall.HostHasIPv6("nb-test0") {
		t.Skip("host has no IPv6")
	}
	t.Setenv(firewall.EnvAllowUnfilteredIPv6, "true")

	ns := fwtest.NewPeerNamespace(t)
	addr := ns.ListenHost(t)

	manager, err := Create(overlayOnlyV4(ns.IfaceName), iface.DefaultMTU)
	require.NoError(t, err, "create manager")
	t.Cleanup(func() { _ = manager.Close(nil) })
	require.NoError(t, manager.Init(nil))

	assert.False(t, manager.hasV6Family(), "no IPv6 family when the operator allows unfiltered IPv6")
	assert.False(t, hasIPv6Table(t), "no ip6 table when the operator allows unfiltered IPv6")
	ns.WaitDial(t, addr, "IPv6 is left to the host's rules")
}

// The accept NetBird puts into a host's dual-stack table covers IPv6 as well. On a host whose
// input policy is drop that accept is what lets the interface's traffic in, so the IPv6 deny has
// to hold with the accept in place.
func TestNftablesManagerDropsIPv6BehindHostAcceptInInetTable(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}
	if !firewall.HostHasIPv6("nb-test0") {
		t.Skip("host has no IPv6")
	}
	if err := probeIPv6Filtering(); err != nil {
		t.Skipf("nftables cannot filter IPv6: %v", err)
	}

	ns := fwtest.NewPeerNamespace(t)
	addr := ns.ListenHost(t)
	ns.WaitDial(t, addr, "control: connection without any firewall")

	const hostTable = "nbtest-hostdrop"
	host := &nftables.Conn{}
	table := host.AddTable(&nftables.Table{Name: hostTable, Family: nftables.TableFamilyINet})
	host.AddChain(&nftables.Chain{
		Name:     "input",
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &dropPolicy,
	})
	require.NoError(t, host.Flush(), "create the host's default-drop table")
	t.Cleanup(func() {
		c := &nftables.Conn{}
		c.DelTable(table)
		_ = c.Flush()
	})
	require.Error(t, ns.Dial(addr), "control: the host's own policy drops the connection")

	manager, err := Create(overlayOnlyV4(ns.IfaceName), iface.DefaultMTU)
	require.NoError(t, err, "create manager")
	t.Cleanup(func() { _ = manager.Close(nil) })
	require.NoError(t, manager.Init(nil))

	require.Equal(t, 1, countAcceptRules(t, nftables.TableFamilyINet, hostTable), "NetBird's accept must be in the host's chain")
	assert.Error(t, ns.Dial(addr), "IPv6 must still be dropped behind NetBird's accept in the host's chain")

	require.NoError(t, manager.Close(nil))
	assert.Equal(t, 0, countAcceptRules(t, nftables.TableFamilyINet, hostTable), "Close must remove NetBird's accept from the host's chain")
}

var dropPolicy = nftables.ChainPolicyDrop
