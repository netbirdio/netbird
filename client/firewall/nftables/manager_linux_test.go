package nftables

import (
	"fmt"
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
		fw.RuleDirectionIN,
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
			Offset:       2,
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

func TestNFtablesCreatePerformance(t *testing.T) {
	for _, testMax := range []int{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000} {
		t.Run(fmt.Sprintf("Testing %d rules", testMax), func(t *testing.T) {
			// just check on the local interface
			manager, err := Create("lo")
			require.NoError(t, err)
			time.Sleep(time.Second)

			defer func() {
				if err := manager.Reset(); err != nil {
					t.Errorf("clear the manager state: %v", err)
				}
				time.Sleep(time.Second)
			}()

			ip := net.ParseIP("10.20.0.100")
			start := time.Now()
			for i := 0; i < testMax; i++ {
				port := &fw.Port{Values: []int{1000 + i}}
				if i%2 == 0 {
					_, err = manager.AddFiltering(ip, "tcp", nil, port, fw.RuleDirectionOUT, fw.ActionAccept, "accept HTTP traffic")
				} else {
					_, err = manager.AddFiltering(ip, "tcp", nil, port, fw.RuleDirectionIN, fw.ActionAccept, "accept HTTP traffic")
				}

				require.NoError(t, err, "failed to add rule")
			}
			t.Logf("execution avg per rule: %s", time.Since(start)/time.Duration(testMax))
		})
	}
}
