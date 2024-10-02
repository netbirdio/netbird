package nftables

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/iface"
)

var ifaceMock = &iFaceMock{
	NameFunc: func() string {
		return "lo"
	},
	AddressFunc: func() iface.WGAddress {
		return iface.WGAddress{
			IP: net.ParseIP("100.96.0.1"),
			Network: &net.IPNet{
				IP:   net.ParseIP("100.96.0.0"),
				Mask: net.IPv4Mask(255, 255, 255, 0),
			},
		}
	},
}

// iFaceMapper defines subset methods of interface required for manager
type iFaceMock struct {
	NameFunc    func() string
	AddressFunc func() iface.WGAddress
}

func (i *iFaceMock) Name() string {
	if i.NameFunc != nil {
		return i.NameFunc()
	}
	panic("NameFunc is not set")
}

func (i *iFaceMock) Address() iface.WGAddress {
	if i.AddressFunc != nil {
		return i.AddressFunc()
	}
	panic("AddressFunc is not set")
}

func (i *iFaceMock) IsUserspaceBind() bool { return false }

func TestNftablesManager(t *testing.T) {

	// just check on the local interface
	manager, err := Create(context.Background(), ifaceMock)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	defer func() {
		err = manager.Reset()
		require.NoError(t, err, "failed to reset")
		time.Sleep(time.Second)
	}()

	ip := net.ParseIP("100.96.0.1")

	testClient := &nftables.Conn{}

	rule, err := manager.AddPeerFiltering(
		ip,
		fw.ProtocolTCP,
		nil,
		&fw.Port{Values: []int{53}},
		fw.RuleDirectionIN,
		fw.ActionDrop,
		"",
		"",
	)
	require.NoError(t, err, "failed to add rule")

	err = manager.Flush()
	require.NoError(t, err, "failed to flush")

	rules, err := testClient.GetRules(manager.aclManager.workTable, manager.aclManager.chainInputRules)
	require.NoError(t, err, "failed to get rules")

	require.Len(t, rules, 2, "expected 2 rules")

	expectedExprs1 := []expr.Any{
		&expr.Ct{
			Key:      expr.CtKeySTATE,
			Register: 1,
		},
		&expr.Bitwise{
			SourceRegister: 1,
			DestRegister:   1,
			Len:            4,
			Mask:           binaryutil.NativeEndian.PutUint32(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED),
			Xor:            binaryutil.NativeEndian.PutUint32(0),
		},
		&expr.Cmp{
			Op:       expr.CmpOpNeq,
			Register: 1,
			Data:     []byte{0, 0, 0, 0},
		},
		&expr.Verdict{
			Kind: expr.VerdictAccept,
		},
	}
	require.ElementsMatch(t, rules[0].Exprs, expectedExprs1, "expected the same expressions")

	ipToAdd, _ := netip.AddrFromSlice(ip)
	add := ipToAdd.Unmap()
	expectedExprs2 := []expr.Any{
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
	require.ElementsMatch(t, rules[1].Exprs, expectedExprs2, "expected the same expressions")

	for _, r := range rule {
		err = manager.DeletePeerRule(r)
		require.NoError(t, err, "failed to delete rule")
	}

	err = manager.Flush()
	require.NoError(t, err, "failed to flush")

	rules, err = testClient.GetRules(manager.aclManager.workTable, manager.aclManager.chainInputRules)
	require.NoError(t, err, "failed to get rules")
	// established rule remains
	require.Len(t, rules, 1, "expected 1 rules after deletion")

	err = manager.Reset()
	require.NoError(t, err, "failed to reset")
}

func TestNFtablesCreatePerformance(t *testing.T) {
	mock := &iFaceMock{
		NameFunc: func() string {
			return "lo"
		},
		AddressFunc: func() iface.WGAddress {
			return iface.WGAddress{
				IP: net.ParseIP("100.96.0.1"),
				Network: &net.IPNet{
					IP:   net.ParseIP("100.96.0.0"),
					Mask: net.IPv4Mask(255, 255, 255, 0),
				},
			}
		},
	}

	for _, testMax := range []int{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000} {
		t.Run(fmt.Sprintf("Testing %d rules", testMax), func(t *testing.T) {
			// just check on the local interface
			manager, err := Create(context.Background(), mock)
			require.NoError(t, err)
			time.Sleep(time.Second * 3)

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
					_, err = manager.AddPeerFiltering(ip, "tcp", nil, port, fw.RuleDirectionOUT, fw.ActionAccept, "", "accept HTTP traffic")
				} else {
					_, err = manager.AddPeerFiltering(ip, "tcp", nil, port, fw.RuleDirectionIN, fw.ActionAccept, "", "accept HTTP traffic")
				}
				require.NoError(t, err, "failed to add rule")

				if i%100 == 0 {
					err = manager.Flush()
					require.NoError(t, err, "failed to flush")
				}
			}

			t.Logf("execution avg per rule: %s", time.Since(start)/time.Duration(testMax))
		})
	}
}
