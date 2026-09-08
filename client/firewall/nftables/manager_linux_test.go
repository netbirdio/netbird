//go:build privileged

package nftables

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os/exec"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

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
			IP:      netip.MustParseAddr("100.96.0.1"),
			Network: netip.MustParsePrefix("100.96.0.0/16"),
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

func TestNftablesManager(t *testing.T) {

	// just check on the local interface
	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))
	time.Sleep(time.Second * 3)

	defer func() {
		err = manager.Close(nil)
		require.NoError(t, err, "failed to reset")
		time.Sleep(time.Second)
	}()

	ip := netip.MustParseAddr("100.96.0.1").Unmap()

	testClient := &nftables.Conn{}

	rule, err := manager.AddFilterRule(nil, pfx(ip.AsSlice()), fw.Network{}, fw.ProtocolTCP, nil, &fw.Port{Values: []uint16{53}}, fw.ActionDrop)
	require.NoError(t, err, "failed to add rule")

	err = manager.Flush()
	require.NoError(t, err, "failed to flush")

	rules, err := testClient.GetRules(manager.family4.workTable, manager.family4.chainInputRules)
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
		&expr.Counter{},
		&expr.Verdict{
			Kind: expr.VerdictAccept,
		},
	}
	// Since DROP rules are inserted at position 0, the DROP rule comes first
	expectedDropExprs := []expr.Any{
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
			Data:     ip.AsSlice(),
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

	// Compare DROP rule at position 0 (inserted first due to InsertRule)
	compareExprsIgnoringCounters(t, rules[0].Exprs, expectedDropExprs)

	// Compare connection tracking rule at position 1 (pushed down by DROP rule insertion)
	compareExprsIgnoringCounters(t, rules[1].Exprs, expectedExprs1)

	require.NoError(t, manager.DeleteFilterRule(rule), "failed to delete rule")

	err = manager.Flush()
	require.NoError(t, err, "failed to flush")

	rules, err = testClient.GetRules(manager.family4.workTable, manager.family4.chainInputRules)
	require.NoError(t, err, "failed to get rules")
	// established rule remains
	require.Len(t, rules, 1, "expected 1 rules after deletion")

	err = manager.Close(nil)
	require.NoError(t, err, "failed to reset")
}

func TestNftablesManagerRuleOrder(t *testing.T) {
	// This test verifies rule insertion order in nftables peer ACLs
	// We add accept rule first, then deny rule to test ordering behavior
	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	defer func() {
		err = manager.Close(nil)
		require.NoError(t, err)
	}()

	ip := netip.MustParseAddr("100.96.0.2").Unmap()
	testClient := &nftables.Conn{}

	// Add accept rule first
	_, err = manager.AddFilterRule(nil, pfx(ip.AsSlice()), fw.Network{}, fw.ProtocolTCP, nil, &fw.Port{Values: []uint16{80}}, fw.ActionAccept)
	require.NoError(t, err, "failed to add accept rule")

	// Add deny rule second for the same traffic
	_, err = manager.AddFilterRule(nil, pfx(ip.AsSlice()), fw.Network{}, fw.ProtocolTCP, nil, &fw.Port{Values: []uint16{80}}, fw.ActionDrop)
	require.NoError(t, err, "failed to add deny rule")

	err = manager.Flush()
	require.NoError(t, err, "failed to flush")

	rules, err := testClient.GetRules(manager.family4.workTable, manager.family4.chainInputRules)
	require.NoError(t, err, "failed to get rules")

	t.Logf("Found %d rules in nftables chain", len(rules))

	// Single-source rules emit a direct payload+cmp on the source IP
	// (no set lookup). Match by source-IP + port + verdict instead of
	// the legacy per-(action,port) set names ("deny-http"/"accept-http")
	// that this test predates.
	wantSrc := ip.AsSlice()
	var acceptRuleIndex, denyRuleIndex = -1, -1
	for i, rule := range rules {
		var hasSrc, hasPort80 bool
		var action string
		for _, e := range rule.Exprs {
			if cmp, ok := e.(*expr.Cmp); ok && cmp.Op == expr.CmpOpEq {
				if bytes.Equal(cmp.Data, wantSrc) {
					hasSrc = true
				}
				if len(cmp.Data) == 2 && binary.BigEndian.Uint16(cmp.Data) == 80 {
					hasPort80 = true
				}
			}
			if verdict, ok := e.(*expr.Verdict); ok {
				switch verdict.Kind {
				case expr.VerdictAccept:
					action = "ACCEPT"
				case expr.VerdictDrop:
					action = "DROP"
				}
			}
		}

		if !hasSrc || !hasPort80 {
			continue
		}
		switch action {
		case "ACCEPT":
			t.Logf("Rule [%d]: src=%s port=80 ACCEPT", i, ip)
			acceptRuleIndex = i
		case "DROP":
			t.Logf("Rule [%d]: src=%s port=80 DROP", i, ip)
			denyRuleIndex = i
		}
	}

	require.NotEqual(t, -1, acceptRuleIndex, "accept rule should exist in nftables")
	require.NotEqual(t, -1, denyRuleIndex, "deny rule should exist in nftables")
	require.Less(t, denyRuleIndex, acceptRuleIndex,
		"deny rule should come before accept rule in nftables chain (deny at index %d, accept at index %d)",
		denyRuleIndex, acceptRuleIndex)
}

func TestNFtablesCreatePerformance(t *testing.T) {
	mock := &iFaceMock{
		NameFunc: func() string {
			return "wg-test"
		},
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.96.0.1"),
				Network: netip.MustParsePrefix("100.96.0.0/16"),
			}
		},
	}

	for _, testMax := range []int{10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000} {
		t.Run(fmt.Sprintf("Testing %d rules", testMax), func(t *testing.T) {
			// just check on the local interface
			manager, err := Create(mock, iface.DefaultMTU)
			require.NoError(t, err)
			require.NoError(t, manager.Init(nil))
			time.Sleep(time.Second * 3)

			defer func() {
				if err := manager.Close(nil); err != nil {
					t.Errorf("clear the manager state: %v", err)
				}
				time.Sleep(time.Second)
			}()

			ip := netip.MustParseAddr("10.20.0.100")
			start := time.Now()
			for i := 0; i < testMax; i++ {
				port := &fw.Port{Values: []uint16{uint16(1000 + i)}}
				_, err = manager.AddFilterRule(nil, pfx(ip.AsSlice()), fw.Network{}, "tcp", nil, port, fw.ActionAccept)
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

func runIptablesSave(t *testing.T) (string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("iptables-save")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	require.NoError(t, err, "iptables-save failed to run")

	return stdout.String(), stderr.String()
}

func verifyIptablesOutput(t *testing.T, stdout, stderr string) {
	t.Helper()
	// Check for any incompatibility warnings
	require.NotContains(t,
		stderr,
		"incompatible",
		"iptables-save produced compatibility warning. Full stderr: %s",
		stderr,
	)

	// Verify standard tables are present
	expectedTables := []string{
		"*filter",
		"*nat",
		"*mangle",
	}

	for _, table := range expectedTables {
		require.Contains(t,
			stdout,
			table,
			"iptables-save output missing expected table: %s\nFull stdout: %s",
			table,
			stdout,
		)
	}
}

func TestNftablesManagerCompatibilityWithIptables(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}

	if _, err := exec.LookPath("iptables-save"); err != nil {
		t.Skipf("iptables-save not available on this system: %v", err)
	}

	// First ensure iptables-nft tables exist by running iptables-save
	stdout, stderr := runIptablesSave(t)
	verifyIptablesOutput(t, stdout, stderr)

	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err, "failed to create manager")
	require.NoError(t, manager.Init(nil))

	t.Cleanup(func() {
		err := manager.Close(nil)
		require.NoError(t, err, "failed to reset manager state")

		// Verify iptables output after reset
		stdout, stderr := runIptablesSave(t)
		verifyIptablesOutput(t, stdout, stderr)
	})

	ip := netip.MustParseAddr("100.96.0.1")
	_, err = manager.AddFilterRule(nil, pfx(ip.AsSlice()), fw.Network{}, fw.ProtocolTCP, nil, &fw.Port{Values: []uint16{80}}, fw.ActionAccept)
	require.NoError(t, err, "failed to add peer filtering rule")

	_, err = manager.AddFilterRule(
		nil,
		[]netip.Prefix{netip.MustParsePrefix("192.168.2.0/24")},
		fw.Network{Prefix: netip.MustParsePrefix("10.1.0.0/24")},
		fw.ProtocolTCP,
		nil,
		&fw.Port{Values: []uint16{443}},
		fw.ActionAccept,
	)
	require.NoError(t, err, "failed to add route filtering rule")

	pair := fw.RouterPair{
		Source:      fw.Network{Prefix: netip.MustParsePrefix("192.168.1.0/24")},
		Destination: fw.Network{Prefix: netip.MustParsePrefix("10.0.0.0/24")},
		Masquerade:  true,
	}
	err = manager.AddNatRule(pair)
	require.NoError(t, err, "failed to add NAT rule")

	dnatRule, err := manager.AddDNATRule(fw.ForwardRule{
		Protocol:          fw.ProtocolTCP,
		DestinationPort:   fw.Port{Values: []uint16{8080}},
		TranslatedAddress: netip.MustParseAddr("100.96.0.2"),
		TranslatedPort:    fw.Port{Values: []uint16{80}},
	})
	require.NoError(t, err, "failed to add DNAT rule")

	t.Cleanup(func() {
		require.NoError(t, manager.DeleteDNATRule(dnatRule), "failed to delete DNAT rule")
	})

	stdout, stderr = runIptablesSave(t)
	verifyIptablesOutput(t, stdout, stderr)
}

func TestNftablesManagerIPv6CompatibilityWithIp6tables(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}

	for _, bin := range []string{"ip6tables", "ip6tables-save", "iptables-save"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available on this system: %v", bin, err)
		}
	}

	// Seed ip6 tables in the nft backend. Docker may not create them.
	seedIp6tables(t)

	ifaceMockV6 := &iFaceMock{
		NameFunc: func() string { return "wt-test" },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.96.0.1"),
				Network: netip.MustParsePrefix("100.96.0.0/16"),
				IPv6:    netip.MustParseAddr("fd00::1"),
				IPv6Net: netip.MustParsePrefix("fd00::/64"),
			}
		},
	}

	manager, err := Create(ifaceMockV6, iface.DefaultMTU)
	require.NoError(t, err, "create manager")
	require.NoError(t, manager.Init(nil))

	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil), "close manager")

		stdout, stderr := runIp6tablesSave(t)
		verifyIp6tablesOutput(t, stdout, stderr)
	})

	ip := netip.MustParseAddr("fd00::2")
	_, err = manager.AddFilterRule(nil, pfx(ip.AsSlice()), fw.Network{}, fw.ProtocolTCP, nil, &fw.Port{Values: []uint16{80}}, fw.ActionAccept)
	require.NoError(t, err, "add v6 peer filtering rule")

	_, err = manager.AddFilterRule(
		nil,
		[]netip.Prefix{netip.MustParsePrefix("fd00:1::/64")},
		fw.Network{Prefix: netip.MustParsePrefix("2001:db8::/48")},
		fw.ProtocolTCP,
		nil,
		&fw.Port{Values: []uint16{443}},
		fw.ActionAccept,
	)
	require.NoError(t, err, "add v6 route filtering rule")

	err = manager.AddNatRule(fw.RouterPair{
		Source:      fw.Network{Prefix: netip.MustParsePrefix("fd00::/64")},
		Destination: fw.Network{Prefix: netip.MustParsePrefix("2001:db8::/48")},
		Masquerade:  true,
	})
	require.NoError(t, err, "add v6 NAT rule")

	dnatRule, err := manager.AddDNATRule(fw.ForwardRule{
		Protocol:          fw.ProtocolTCP,
		DestinationPort:   fw.Port{Values: []uint16{8080}},
		TranslatedAddress: netip.MustParseAddr("fd00::2"),
		TranslatedPort:    fw.Port{Values: []uint16{80}},
	})
	require.NoError(t, err, "add v6 DNAT rule")

	t.Cleanup(func() {
		require.NoError(t, manager.DeleteDNATRule(dnatRule), "delete v6 DNAT rule")
	})

	stdout, stderr := runIptablesSave(t)
	verifyIptablesOutput(t, stdout, stderr)

	stdout, stderr = runIp6tablesSave(t)
	verifyIp6tablesOutput(t, stdout, stderr)
}

func seedIp6tables(t *testing.T) {
	t.Helper()
	for _, tc := range []struct{ table, chain string }{
		{"filter", "FORWARD"},
		{"nat", "POSTROUTING"},
		{"mangle", "FORWARD"},
	} {
		add := exec.Command("ip6tables", "-t", tc.table, "-A", tc.chain, "-j", "ACCEPT")
		require.NoError(t, add.Run(), "seed ip6tables -t %s", tc.table)
		del := exec.Command("ip6tables", "-t", tc.table, "-D", tc.chain, "-j", "ACCEPT")
		require.NoError(t, del.Run(), "unseed ip6tables -t %s", tc.table)
	}
}

func runIp6tablesSave(t *testing.T) (string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := exec.Command("ip6tables-save")
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	require.NoError(t, cmd.Run(), "ip6tables-save failed")
	return stdout.String(), stderr.String()
}

func verifyIp6tablesOutput(t *testing.T, stdout, stderr string) {
	t.Helper()
	for _, msg := range []string{
		"Table `nat' is incompatible",
		"Table `mangle' is incompatible",
		"Table `filter' is incompatible",
	} {
		require.NotContains(t, stdout, msg,
			"ip6tables-save stdout reports incompatibility: %s", stdout)
		require.NotContains(t, stderr, msg,
			"ip6tables-save stderr reports incompatibility: %s", stderr)
	}
}

func TestNftablesManagerCompatibilityWithIptablesFor6kPrefixes(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}

	if _, err := exec.LookPath("iptables-save"); err != nil {
		t.Skipf("iptables-save not available on this system: %v", err)
	}

	// First ensure iptables-nft tables exist by running iptables-save
	stdout, stderr := runIptablesSave(t)
	verifyIptablesOutput(t, stdout, stderr)

	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err, "failed to create manager")
	require.NoError(t, manager.Init(nil))

	t.Cleanup(func() {
		err := manager.Close(nil)
		require.NoError(t, err, "failed to reset manager state")

		// Verify iptables output after reset
		stdout, stderr := runIptablesSave(t)
		verifyIptablesOutput(t, stdout, stderr)
	})

	const octet2Count = 25
	const octet3Count = 255
	prefixes := make([]netip.Prefix, 0, (octet2Count-1)*(octet3Count-1))
	for i := 1; i < octet2Count; i++ {
		for j := 1; j < octet3Count; j++ {
			addr := netip.AddrFrom4([4]byte{192, byte(j), byte(i), 0})
			prefixes = append(prefixes, netip.PrefixFrom(addr, 24))
		}
	}
	_, err = manager.AddFilterRule(
		nil,
		prefixes,
		fw.Network{Prefix: netip.MustParsePrefix("10.2.0.0/24")},
		fw.ProtocolTCP,
		nil,
		&fw.Port{Values: []uint16{443}},
		fw.ActionAccept,
	)
	require.NoError(t, err, "failed to add route filtering rule")

	stdout, stderr = runIptablesSave(t)
	verifyIptablesOutput(t, stdout, stderr)
}

func TestNftablesManagerCompatibilityWithIptablesForWildcardSource(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}

	if _, err := exec.LookPath("iptables-save"); err != nil {
		t.Skipf("iptables-save not available on this system: %v", err)
	}

	// First ensure iptables-nft tables exist by running iptables-save
	stdout, stderr := runIptablesSave(t)
	verifyIptablesOutput(t, stdout, stderr)

	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err, "failed to create manager")
	require.NoError(t, manager.Init(nil))

	t.Cleanup(func() {
		err := manager.Close(nil)
		require.NoError(t, err, "failed to reset manager state")

		// Verify iptables output after reset
		stdout, stderr := runIptablesSave(t)
		verifyIptablesOutput(t, stdout, stderr)
	})

	_, err = manager.AddFilterRule(
		nil,
		[]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		fw.Network{Prefix: netip.MustParsePrefix("10.2.0.0/24")},
		fw.ProtocolTCP,
		nil,
		&fw.Port{Values: []uint16{443}},
		fw.ActionAccept,
	)
	require.NoError(t, err, "failed to add route filtering rule")

	stdout, stderr = runIptablesSave(t)
	verifyIptablesOutput(t, stdout, stderr)
}

func TestNftablesManagerMultiPortFilter(t *testing.T) {
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}

	manager, err := Create(ifaceMock, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.Init(nil))

	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil), "failed to reset manager state")
	})

	ip := netip.MustParseAddr("100.96.0.1")

	rule, err := manager.AddFilterRule(nil, pfx(ip.AsSlice()), fw.Network{}, fw.ProtocolTCP, nil, &fw.Port{Values: []uint16{80, 443}}, fw.ActionAccept)
	require.NoError(t, err, "failed to add multi-port rule")

	testClient := &nftables.Conn{}
	rules, err := testClient.GetRules(manager.family4.workTable, manager.family4.chainInputRules)
	require.NoError(t, err, "failed to get rules")

	var lookup *expr.Lookup
	for _, kernelRule := range rules {
		if string(kernelRule.UserData) != string(rule.ID()) {
			continue
		}
		for _, e := range kernelRule.Exprs {
			if l, ok := e.(*expr.Lookup); ok {
				lookup = l
			}
		}
	}
	require.NotNil(t, lookup, "multi-port rule must match ports via a set lookup")

	sets, err := testClient.GetSets(manager.family4.workTable)
	require.NoError(t, err, "failed to get sets")

	var portSet *nftables.Set
	for _, s := range sets {
		if s.Name == lookup.SetName {
			portSet = s
		}
	}
	require.NotNil(t, portSet, "anonymous port set not found in kernel")

	portSet.Table = manager.family4.workTable
	elements, err := testClient.GetSetElements(portSet)
	require.NoError(t, err, "failed to get set elements")

	ports := make(map[uint16]bool)
	for _, e := range elements {
		require.Len(t, e.Key, 2, "port set element key should be 2 bytes")
		ports[binary.BigEndian.Uint16(e.Key)] = true
	}
	require.True(t, ports[80], "port set should contain port 80")
	require.True(t, ports[443], "port set should contain port 443")

	require.NoError(t, manager.DeleteFilterRule(rule), "failed to delete rule")

	rules, err = testClient.GetRules(manager.family4.workTable, manager.family4.chainInputRules)
	require.NoError(t, err, "failed to get rules after delete")
	for _, kernelRule := range rules {
		require.NotEqual(t, string(rule.ID()), string(kernelRule.UserData), "rule should be removed from kernel")
	}
}

func compareExprsIgnoringCounters(t *testing.T, got, want []expr.Any) {
	t.Helper()
	require.Equal(t, len(got), len(want), "expression count mismatch")

	for i := range got {
		if _, isCounter := got[i].(*expr.Counter); isCounter {
			_, wantIsCounter := want[i].(*expr.Counter)
			require.True(t, wantIsCounter, "expected Counter at index %d", i)
			continue
		}

		require.Equal(t, got[i], want[i], "expression mismatch at index %d", i)
	}
}
