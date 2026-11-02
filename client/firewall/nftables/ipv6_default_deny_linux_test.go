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

	tables, err := (&nftables.Conn{}).ListTablesOfFamily(nftables.TableFamilyIPv6)
	require.NoError(t, err, "list ip6 tables")
	for _, table := range tables {
		if table.Name == getTableName() {
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
	if !firewall.HostHasIPv6() {
		t.Skip("host has no IPv6")
	}

	ns := fwtest.NewPeerNamespace(t)
	addr := ns.ListenHost(t)

	require.NoError(t, ns.Dial(addr), "control: connection without the firewall")

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
	assert.NoError(t, ns.Dial(addr), "connection must work again once the firewall is closed")
}

// countAcceptRules returns how many of the accept rules NetBird puts into host chains are in
// the chain of the given IPv6 table.
func countAcceptRules(t *testing.T, tableName string) int {
	t.Helper()

	conn := &nftables.Conn{}
	chains, err := conn.ListChainsOfTableFamily(nftables.TableFamilyIPv6)
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
	if !firewall.HostHasIPv6() {
		t.Skip("host has no IPv6")
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
	require.NoError(t, host.Flush(), "create host table")
	t.Cleanup(func() {
		c := &nftables.Conn{}
		c.DelTable(table)
		_ = c.Flush()
	})

	statePath := filepath.Join(t.TempDir(), "state.json")
	sm := statemanager.New(statePath)

	manager, err := Create(overlayOnlyV4(ns.IfaceName), iface.DefaultMTU)
	require.NoError(t, err, "create manager")
	require.NoError(t, manager.Init(sm))
	require.NoError(t, sm.PersistState(context.Background()), "persist state")

	require.True(t, hasIPv6Table(t), "the ip6 table must exist while the firewall runs")
	require.Equal(t, 1, countAcceptRules(t, hostTable), "the accept rule must be in the host chain while the firewall runs")
	require.Error(t, ns.Dial(addr), "IPv6 must be dropped while the firewall runs")

	// The process is gone without closing the firewall. The new run finds the saved state and
	// cleans up, and the host has no IPv6 by then.
	hostHasIPv6 = func() bool { return false }
	t.Cleanup(func() { hostHasIPv6 = firewall.HostHasIPv6 })

	recovered := statemanager.New(statePath)
	recovered.RegisterState(&ShutdownState{})
	require.NoError(t, recovered.PerformCleanup(), "crash cleanup")

	assert.False(t, hasIPv6Table(t), "crash cleanup must remove the ip6 table")
	assert.Equal(t, 0, countAcceptRules(t, hostTable), "crash cleanup must remove the accept rule from the host chain")
	assert.NoError(t, ns.Dial(addr), "connection must work again after the crash cleanup")

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
	assert.Equal(t, hostHasIPv6(), m.hasV6Family(), "the deny exists exactly when the host has IPv6")

	_, err = m.AddFilterRule(nil, []netip.Prefix{netip.MustParsePrefix("fd00::2/128")}, firewall.Network{}, firewall.ProtocolALL, nil, nil, firewall.ActionAccept)
	assert.ErrorIs(t, err, firewall.ErrIPv6NotInitialized, "IPv6 rules are still refused without an overlay address")
}
