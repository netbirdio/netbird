package iptables

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

func iptRefcountIfaceV4() *iFaceMock {
	return &iFaceMock{
		NameFunc: func() string { return "wt-refcount" },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("10.20.0.1"),
				Network: netip.MustParsePrefix("10.20.0.0/24"),
			}
		},
	}
}

func iptRefcountIfaceDual() *iFaceMock {
	return &iFaceMock{
		NameFunc: func() string { return "wt-refcount" },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("10.20.0.1"),
				Network: netip.MustParsePrefix("10.20.0.0/24"),
				IPv6:    netip.MustParseAddr("fd00::1"),
				IPv6Net: netip.MustParsePrefix("fd00::/64"),
			}
		},
	}
}

func newIptRefcountManager(t *testing.T, dual bool) *Manager {
	t.Helper()
	var ifMock *iFaceMock
	if dual {
		ifMock = iptRefcountIfaceDual()
	} else {
		ifMock = iptRefcountIfaceV4()
	}
	m, err := Create(ifMock, iface.DefaultMTU)
	require.NoError(t, err, "create manager")
	require.NoError(t, m.Init(nil), "init manager")
	t.Cleanup(func() {
		require.NoError(t, m.Close(nil), "close manager")
	})
	return m
}

func iptDnatV4(port uint16) fw.ForwardRule {
	return fw.ForwardRule{
		Protocol:          fw.ProtocolTCP,
		DestinationPort:   fw.Port{Values: []uint16{port}},
		TranslatedAddress: netip.MustParseAddr("10.20.0.2"),
		TranslatedPort:    fw.Port{Values: []uint16{80}},
	}
}

func iptDnatV6(port uint16) fw.ForwardRule {
	return fw.ForwardRule{
		Protocol:          fw.ProtocolTCP,
		DestinationPort:   fw.Port{Values: []uint16{port}},
		TranslatedAddress: netip.MustParseAddr("fd00::2"),
		TranslatedPort:    fw.Port{Values: []uint16{80}},
	}
}

// TestIptablesDNAT_RefcountBalancedV4 covers a Balanced Add/Delete pair on v4.
func TestIptablesDNAT_RefcountBalancedV4(t *testing.T) {
	m := newIptRefcountManager(t, false)
	state := m.router.ipFwdState

	r1, err := m.AddDNATRule(iptDnatV4(7081))
	require.NoError(t, err, "add v4 dnat 1")
	v4, v6 := state.Counts()
	require.Equal(t, 1, v4, "v4 refcount after first add")
	require.Equal(t, 0, v6, "v6 refcount unchanged")

	r2, err := m.AddDNATRule(iptDnatV4(7082))
	require.NoError(t, err, "add v4 dnat 2")
	v4, v6 = state.Counts()
	require.Equal(t, 2, v4, "v4 refcount after second add")
	require.Equal(t, 0, v6, "v6 refcount unchanged")

	require.NoError(t, m.DeleteDNATRule(r1))
	v4, v6 = state.Counts()
	require.Equal(t, 1, v4, "v4 refcount after first delete")
	require.Equal(t, 0, v6, "v6 refcount unchanged")

	require.NoError(t, m.DeleteDNATRule(r2))
	v4, v6 = state.Counts()
	require.Equal(t, 0, v4, "v4 refcount after second delete")
	require.Equal(t, 0, v6, "v6 refcount unchanged")
}

// TestIptablesDNAT_RefcountBalancedV6 checks the v6 path increments v6 only and
// decrements back to zero.
func TestIptablesDNAT_RefcountBalancedV6(t *testing.T) {
	m := newIptRefcountManager(t, true)
	require.NotNil(t, m.router6, "v6 router")
	require.Same(t, m.router.ipFwdState, m.router6.ipFwdState, "shared state")
	state := m.router.ipFwdState

	r1, err := m.AddDNATRule(iptDnatV6(9081))
	require.NoError(t, err, "add v6 dnat 1")
	v4, v6 := state.Counts()
	require.Equal(t, 0, v4)
	require.Equal(t, 1, v6, "v6 refcount after first add")

	r2, err := m.AddDNATRule(iptDnatV6(9082))
	require.NoError(t, err, "add v6 dnat 2")
	v4, v6 = state.Counts()
	require.Equal(t, 0, v4, "v4 refcount unchanged")
	require.Equal(t, 2, v6, "v6 refcount after second add")

	require.NoError(t, m.DeleteDNATRule(r1))
	v4, v6 = state.Counts()
	require.Equal(t, 0, v4, "v4 refcount unchanged")
	require.Equal(t, 1, v6, "v6 refcount after first delete")

	require.NoError(t, m.DeleteDNATRule(r2))
	v4, v6 = state.Counts()
	require.Equal(t, 0, v4)
	require.Equal(t, 0, v6, "v6 refcount after second delete")
}

// TestIptablesDNAT_DuplicateAddNoLeak verifies the duplicate-rule path returns
// without bumping the refcount.
func TestIptablesDNAT_DuplicateAddNoLeak(t *testing.T) {
	m := newIptRefcountManager(t, true)
	state := m.router.ipFwdState

	rule := iptDnatV4(7083)
	r1, err := m.AddDNATRule(rule)
	require.NoError(t, err)
	v4, _ := state.Counts()
	require.Equal(t, 1, v4)

	_, err = m.AddDNATRule(rule)
	require.NoError(t, err, "duplicate add")
	v4, _ = state.Counts()
	require.Equal(t, 1, v4, "duplicate add must not increment")

	require.NoError(t, m.DeleteDNATRule(r1))
	v4, _ = state.Counts()
	require.Equal(t, 0, v4, "single delete must drop to zero")
}

// TestIptablesDNAT_DeleteMissingNoUnderflow verifies Delete on an unknown rule
// neither errors nor releases the refcount.
func TestIptablesDNAT_DeleteMissingNoUnderflow(t *testing.T) {
	m := newIptRefcountManager(t, true)
	state := m.router.ipFwdState

	phantom := iptDnatV4(7099)
	require.NoError(t, m.DeleteDNATRule(&phantom), "delete missing v4")
	v4, v6 := state.Counts()
	require.Equal(t, 0, v4)
	require.Equal(t, 0, v6)

	phantom6 := iptDnatV6(9099)
	require.NoError(t, m.DeleteDNATRule(&phantom6), "delete missing v6")
	v4, v6 = state.Counts()
	require.Equal(t, 0, v4)
	require.Equal(t, 0, v6)

	r1, err := m.AddDNATRule(iptDnatV4(7100))
	require.NoError(t, err)
	v4, _ = state.Counts()
	require.Equal(t, 1, v4, "real add still increments after phantom delete")
	require.NoError(t, m.DeleteDNATRule(r1))
}

// TestIptablesDNAT_DoubleDeleteNoUnderflow verifies a second Delete on the same
// rule is a no-op.
func TestIptablesDNAT_DoubleDeleteNoUnderflow(t *testing.T) {
	m := newIptRefcountManager(t, true)
	state := m.router.ipFwdState

	r1, err := m.AddDNATRule(iptDnatV6(9083))
	require.NoError(t, err)
	_, v6 := state.Counts()
	require.Equal(t, 1, v6)

	require.NoError(t, m.DeleteDNATRule(r1), "first delete")
	_, v6 = state.Counts()
	require.Equal(t, 0, v6)

	require.NoError(t, m.DeleteDNATRule(r1), "second delete must be no-op")
	_, v6 = state.Counts()
	require.Equal(t, 0, v6, "double delete must not underflow")
}
