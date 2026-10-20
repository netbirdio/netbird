//go:build privileged

package nftables

import (
	"bytes"
	"os"
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/iface"
)

// TestInterfaceAllowerInputOnly verifies the userspace-mode allower opens the
// interface on the INPUT hook of foreign chains only (not FORWARD, since the
// userspace router never forwards in the kernel), creates no netbird work
// table, and removes its rules on Close.
func TestInterfaceAllowerInputOnly(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root required")
	}

	require.False(t, ipTableExists(t, getTableName()), "precondition: no stale netbird table")

	conn := &nftables.Conn{}
	extTable := conn.AddTable(&nftables.Table{Name: "nbtest_extchains", Family: nftables.TableFamilyINet})
	inputChain := conn.AddChain(&nftables.Chain{
		Name: "ext_input", Table: extTable,
		Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Type: nftables.ChainTypeFilter,
	})
	forwardChain := conn.AddChain(&nftables.Chain{
		Name: "ext_forward", Table: extTable,
		Hooknum: nftables.ChainHookForward, Priority: nftables.ChainPriorityFilter, Type: nftables.ChainTypeFilter,
	})
	require.NoError(t, conn.Flush(), "create external table and chains")
	t.Cleanup(func() {
		c := &nftables.Conn{}
		c.DelTable(extTable)
		_ = c.Flush()
	})

	allower, err := NewInterfaceAllower(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err, "create allower")
	require.NoError(t, allower.Apply(), "apply")

	require.True(t, chainHasUserData(t, extTable, inputChain, userDataAcceptInputRule),
		"external INPUT chain should get the accept rule")
	require.Len(t, listRules(t, extTable, forwardChain), 0,
		"external FORWARD chain must not be opened in userspace mode")
	require.False(t, ipTableExists(t, getTableName()),
		"allower must not create a netbird work table")

	require.NoError(t, allower.Close(), "close")
	require.False(t, chainHasUserData(t, extTable, inputChain, userDataAcceptInputRule),
		"accept rule should be removed on close")
}

func listRules(t *testing.T, table *nftables.Table, chain *nftables.Chain) []*nftables.Rule {
	t.Helper()
	c := &nftables.Conn{}
	rules, err := c.GetRules(table, chain)
	require.NoError(t, err)
	return rules
}

func chainHasUserData(t *testing.T, table *nftables.Table, chain *nftables.Chain, ud string) bool {
	for _, r := range listRules(t, table, chain) {
		if bytes.Equal(r.UserData, []byte(ud)) {
			return true
		}
	}
	return false
}

func ipTableExists(t *testing.T, name string) bool {
	t.Helper()
	c := &nftables.Conn{}
	for _, fam := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6} {
		tbls, err := c.ListTablesOfFamily(fam)
		require.NoError(t, err)
		for _, tb := range tbls {
			if tb.Name == name {
				return true
			}
		}
	}
	return false
}
