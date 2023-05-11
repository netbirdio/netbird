package nftables

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	fw "github.com/netbirdio/netbird/client/firewall"
)

func TestNftablesManager(t *testing.T) {
	// just check on the local interface
	manager, err := Create("lo")
	require.NoError(t, err)
	time.Sleep(time.Second)

	defer func() {
		err = manager.Reset()
		require.NoError(t, err, "failed to reset")
		time.Sleep(time.Second)
	}()

	ip := net.ParseIP("100.96.0.1")

	testClient := &nftables.Conn{}

	rule, err := manager.AddFiltering(
		ip,
		fw.ProtocolTCP,
		nil,
		&fw.Port{Values: []int{53}},
		fw.DirectionSrc,
		fw.ActionDrop,
		"",
	)
	require.NoError(t, err, "failed to add rule")

	rules, err := testClient.GetRules(manager.tableIPv4, manager.filterInputChainIPv4)
	require.NoError(t, err, "failed to get rules")
	// 1 regular rule and other "drop all rule" for the interface
	require.Len(t, rules, 2, "expected 1 rule")

	ipToAdd, _ := netip.AddrFromSlice(ip)
	add := ipToAdd.Unmap()
	expectedExprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname("lo"),
		},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       uint32(9),
			Len:          uint32(1),
		},
		&expr.Cmp{
			Register: 1,
			Op:       expr.CmpOpEq,
			Data:     []byte{unix.IPPROTO_TCP},
		},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       12,
			Len:          4,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     add.AsSlice(),
		},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       0,
			Len:          2,
		},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     []byte{0, 53},
		},
		&expr.Verdict{Kind: expr.VerdictDrop},
	}
	require.ElementsMatch(t, rules[0].Exprs, expectedExprs, "expected the same expressions")

	err = manager.DeleteRule(rule)
	require.NoError(t, err, "failed to delete rule")

	rules, err = testClient.GetRules(manager.tableIPv4, manager.filterInputChainIPv4)
	require.NoError(t, err, "failed to get rules")
	require.Len(t, rules, 1, "expected 1 rules after deleteion")

	err = manager.Reset()
	require.NoError(t, err, "failed to reset")
}
