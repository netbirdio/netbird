package nftables

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/iface"
)

// iFaceMapper defines subset methods of interface required for manager
type iFaceMock struct {
	NameFunc     func() string
	AddressFunc  func() iface.WGAddress
	Address6Func func() *iface.WGAddress
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

func (i *iFaceMock) Address6() *iface.WGAddress {
	if i.Address6Func != nil {
		return i.Address6Func()
	}
	panic("AddressFunc is not set")
}

func (i *iFaceMock) IsUserspaceBind() bool { return false }

func TestNftablesManager(t *testing.T) {
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
		Address6Func: func() *iface.WGAddress { return nil },
	}

	// just check on the local interface
	manager, err := Create(context.Background(), mock)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

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
		"",
	)
	require.NoError(t, err, "failed to add rule")

	err = manager.Flush()
	require.NoError(t, err, "failed to flush")

	rules, err := testClient.GetRules(manager.aclManager.workTable, manager.aclManager.chainInputRules)
	require.NoError(t, err, "failed to get rules")

	require.Len(t, rules, 1, "expected 1 rules")

	ipToAdd, _ := netip.AddrFromSlice(ip)
	add := ipToAdd.Unmap()
	expectedExprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname("lo"),
		},
		&expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
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

	for _, r := range rule {
		err = manager.DeleteRule(r)
		require.NoError(t, err, "failed to delete rule")
	}

	err = manager.Flush()
	require.NoError(t, err, "failed to flush")

	rules, err = testClient.GetRules(manager.aclManager.workTable, manager.aclManager.chainInputRules)
	require.NoError(t, err, "failed to get rules")
	require.Len(t, rules, 0, "expected 0 rules after deletion")

	err = manager.Reset()
	require.NoError(t, err, "failed to reset")
}

func TestNftablesManager6Disabled(t *testing.T) {
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
		Address6Func: func() *iface.WGAddress { return nil },
	}

	// just check on the local interface
	manager, err := Create(context.Background(), mock)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	defer func() {
		err = manager.Reset()
		require.NoError(t, err, "failed to reset")
		time.Sleep(time.Second)
	}()

	ip := net.ParseIP("2001:db8::fedc:ba09:8765:4321")

	testClient := &nftables.Conn{}

	_, err = manager.AddFiltering(
		ip,
		fw.ProtocolTCP,
		nil,
		&fw.Port{Values: []int{53}},
		fw.RuleDirectionIN,
		fw.ActionDrop,
		"",
		"",
	)
	require.Error(t, err, "IPv6 rule should not be added when IPv6 is disabled")

	err = manager.Flush()
	require.NoError(t, err, "failed to flush")

	rules, err := testClient.GetRules(manager.aclManager.workTable, manager.aclManager.chainInputRules)
	require.NoError(t, err, "failed to get rules")

	require.Len(t, rules, 0, "expected no rules")

	err = manager.Reset()
	require.NoError(t, err, "failed to reset")
}

func TestNftablesManager6(t *testing.T) {

	if !iface.SupportsIPv6() {
		t.Skip("Environment does not support IPv6, skipping IPv6 test...")
	}
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
		Address6Func: func() *iface.WGAddress {
			return &iface.WGAddress{
				IP: net.ParseIP("2001:db8::0123:4567:890a:bcde"),
				Network: &net.IPNet{
					IP:   net.ParseIP("2001:db8::"),
					Mask: net.CIDRMask(64, 128),
				},
			}
		},
	}

	// just check on the local interface
	manager, err := Create(context.Background(), mock)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	defer func() {
		err = manager.Reset()
		require.NoError(t, err, "failed to reset")
		time.Sleep(time.Second)
	}()

	require.True(t, manager.V6Active(), "IPv6 is not active even though it should be.")

	ip := net.ParseIP("2001:db8::fedc:ba09:8765:4321")

	testClient := &nftables.Conn{}

	rule, err := manager.AddFiltering(
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

	rules, err := testClient.GetRules(manager.aclManager.workTable6, manager.aclManager.chainInputRules6)
	require.NoError(t, err, "failed to get rules")

	require.Len(t, rules, 1, "expected 1 rules")

	ipToAdd, _ := netip.AddrFromSlice(ip)
	add := ipToAdd.Unmap()
	expectedExprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname("lo"),
		},
		&expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
		},
		&expr.Cmp{
			Register: 1,
			Op:       expr.CmpOpEq,
			Data:     []byte{unix.IPPROTO_TCP},
		},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       8,
			Len:          16,
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

	for _, r := range rule {
		err = manager.DeleteRule(r)
		require.NoError(t, err, "failed to delete rule")
	}

	err = manager.Flush()
	require.NoError(t, err, "failed to flush")

	rules, err = testClient.GetRules(manager.aclManager.workTable6, manager.aclManager.chainInputRules6)
	require.NoError(t, err, "failed to get rules")
	require.Len(t, rules, 0, "expected 0 rules after deletion")

	err = manager.Reset()
	require.NoError(t, err, "failed to reset")
}

func TestNftablesManagerAddressReset6(t *testing.T) {

	if !iface.SupportsIPv6() {
		t.Skip("Environment does not support IPv6, skipping IPv6 test...")
	}
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
		Address6Func: func() *iface.WGAddress {
			return &iface.WGAddress{
				IP: net.ParseIP("2001:db8::0123:4567:890a:bcde"),
				Network: &net.IPNet{
					IP:   net.ParseIP("2001:db8::"),
					Mask: net.CIDRMask(64, 128),
				},
			}
		},
	}

	// just check on the local interface
	manager, err := Create(context.Background(), mock)
	require.NoError(t, err)
	time.Sleep(time.Second * 3)

	defer func() {
		err = manager.Reset()
		require.NoError(t, err, "failed to reset")
		time.Sleep(time.Second)
	}()

	require.True(t, manager.V6Active(), "IPv6 is not active even though it should be.")

	ip := net.ParseIP("2001:db8::fedc:ba09:8765:4321")

	testClient := &nftables.Conn{}

	_, err = manager.AddFiltering(
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

	rules, err := testClient.GetRules(manager.aclManager.workTable6, manager.aclManager.chainInputRules6)
	require.NoError(t, err, "failed to get rules")

	require.Len(t, rules, 1, "expected 1 rules")

	mock.Address6Func = func() *iface.WGAddress {
		return nil
	}

	err = manager.ResetV6Firewall()
	require.NoError(t, err, "failed to reset IPv6 firewall")

	err = manager.Flush()
	require.NoError(t, err, "failed to flush")

	require.False(t, manager.V6Active(), "IPv6 is active even though it shouldn't be.")

	tables, err := testClient.ListTablesOfFamily(nftables.TableFamilyIPv6)
	require.NoError(t, err, "failed to list IPv6 tables")

	for _, table := range tables {
		if table.Name == tableName {
			t.Errorf("When IPv6 is disabled, the netbird table should not exist.")
		}
	}

	mock.Address6Func = func() *iface.WGAddress {
		return &iface.WGAddress{
			IP: net.ParseIP("2001:db8::0123:4567:890a:bcdf"),
			Network: &net.IPNet{
				IP:   net.ParseIP("2001:db8::"),
				Mask: net.CIDRMask(64, 128),
			},
		}
	}

	err = manager.ResetV6Firewall()
	require.NoError(t, err, "failed to reset IPv6 firewall")

	require.True(t, manager.V6Active(), "IPv6 is not active even though it should be.")

	rule, err := manager.AddFiltering(
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

	rules, err = testClient.GetRules(manager.aclManager.workTable6, manager.aclManager.chainInputRules6)
	require.NoError(t, err, "failed to get rules")

	require.Len(t, rules, 1, "expected 1 rule")

	ipToAdd, _ := netip.AddrFromSlice(ip)
	add := ipToAdd.Unmap()
	expectedExprs := []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{
			Op:       expr.CmpOpEq,
			Register: 1,
			Data:     ifname("lo"),
		},
		&expr.Meta{
			Key:      expr.MetaKeyL4PROTO,
			Register: 1,
		},
		&expr.Cmp{
			Register: 1,
			Op:       expr.CmpOpEq,
			Data:     []byte{unix.IPPROTO_TCP},
		},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       8,
			Len:          16,
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

	for _, r := range rule {
		err = manager.DeleteRule(r)
		require.NoError(t, err, "failed to delete rule")
	}

	err = manager.Flush()
	require.NoError(t, err, "failed to flush")

	rules, err = testClient.GetRules(manager.aclManager.workTable6, manager.aclManager.chainInputRules6)
	require.NoError(t, err, "failed to get rules")
	require.Len(t, rules, 0, "expected 0 rules after deletion")

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
		Address6Func: func() *iface.WGAddress {
			v6addr, v6net, _ := net.ParseCIDR("fd00:1234:dead:beef::1/64")
			return &iface.WGAddress{
				IP: v6addr,
				Network: &net.IPNet{
					IP:   v6net.IP,
					Mask: v6net.Mask,
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
					_, err = manager.AddFiltering(ip, "tcp", nil, port, fw.RuleDirectionOUT, fw.ActionAccept, "", "accept HTTP traffic")
				} else {
					_, err = manager.AddFiltering(ip, "tcp", nil, port, fw.RuleDirectionIN, fw.ActionAccept, "", "accept HTTP traffic")
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
