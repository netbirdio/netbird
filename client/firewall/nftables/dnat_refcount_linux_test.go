package nftables

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

func nftRefcountIfaceV4() *iFaceMock {
	return &iFaceMock{
		NameFunc: func() string { return "wt-refcount" },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.96.0.1"),
				Network: netip.MustParsePrefix("100.96.0.0/16"),
			}
		},
	}
}

func nftRefcountIfaceDual() *iFaceMock {
	return &iFaceMock{
		NameFunc: func() string { return "wt-refcount" },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      netip.MustParseAddr("100.96.0.1"),
				Network: netip.MustParsePrefix("100.96.0.0/16"),
				IPv6:    netip.MustParseAddr("fd00::1"),
				IPv6Net: netip.MustParsePrefix("fd00::/64"),
			}
		},
	}
}

func newNftRefcountManager(t *testing.T, dual bool) *Manager {
	t.Helper()
	if check() != NFTABLES {
		t.Skip("nftables not supported on this system")
	}
	var ifMock *iFaceMock
	if dual {
		ifMock = nftRefcountIfaceDual()
	} else {
		ifMock = nftRefcountIfaceV4()
	}
	m, err := Create(ifMock, iface.DefaultMTU)
	require.NoError(t, err, "create manager")
	require.NoError(t, m.Init(nil), "init manager")
	t.Cleanup(func() {
		require.NoError(t, m.Close(nil), "close manager")
	})
	return m
}

func dnatV4(port uint16) fw.ForwardRule {
	return fw.ForwardRule{
		Protocol:          fw.ProtocolTCP,
		DestinationPort:   fw.Port{Values: []uint16{port}},
		TranslatedAddress: netip.MustParseAddr("100.96.0.2"),
		TranslatedPort:    fw.Port{Values: []uint16{80}},
	}
}

func dnatV6(port uint16) fw.ForwardRule {
	return fw.ForwardRule{
		Protocol:          fw.ProtocolTCP,
		DestinationPort:   fw.Port{Values: []uint16{port}},
		TranslatedAddress: netip.MustParseAddr("fd00::2"),
		TranslatedPort:    fw.Port{Values: []uint16{80}},
	}
}

// TestNftablesDNAT_RefcountBalancedV4 verifies that Add/Delete pairs leave the
// v4 refcount at zero.
func TestNftablesDNAT_RefcountBalancedV4(t *testing.T) {
	m := newNftRefcountManager(t, false)
	state := m.router.ipFwdState

	r1, err := m.AddDNATRule(dnatV4(8081))
	require.NoError(t, err, "add v4 dnat 1")
	v4, v6 := state.Counts()
	require.Equal(t, 1, v4, "v4 refcount after first add")
	require.Equal(t, 0, v6, "v6 refcount unchanged")

	r2, err := m.AddDNATRule(dnatV4(8082))
	require.NoError(t, err, "add v4 dnat 2")
	v4, v6 = state.Counts()
	require.Equal(t, 2, v4, "v4 refcount after second add")
	require.Equal(t, 0, v6, "v6 refcount unchanged")

	require.NoError(t, m.DeleteDNATRule(r1), "delete v4 dnat 1")
	v4, v6 = state.Counts()
	require.Equal(t, 1, v4, "v4 refcount after first delete")
	require.Equal(t, 0, v6, "v6 refcount unchanged")

	require.NoError(t, m.DeleteDNATRule(r2), "delete v4 dnat 2")
	v4, v6 = state.Counts()
	require.Equal(t, 0, v4, "v4 refcount after second delete")
	require.Equal(t, 0, v6, "v6 refcount unchanged")
}

// TestNftablesDNAT_RefcountBalancedV6 verifies the v6 path increments v6 only
// and decrements back to zero on Delete.
func TestNftablesDNAT_RefcountBalancedV6(t *testing.T) {
	m := newNftRefcountManager(t, true)
	require.NotNil(t, m.router6, "v6 router")
	require.Same(t, m.router.ipFwdState, m.router6.ipFwdState, "shared state")
	state := m.router.ipFwdState

	r1, err := m.AddDNATRule(dnatV6(9091))
	require.NoError(t, err, "add v6 dnat 1")
	v4, v6 := state.Counts()
	require.Equal(t, 0, v4, "v4 refcount unchanged")
	require.Equal(t, 1, v6, "v6 refcount after first add")

	r2, err := m.AddDNATRule(dnatV6(9092))
	require.NoError(t, err, "add v6 dnat 2")
	v4, v6 = state.Counts()
	require.Equal(t, 0, v4)
	require.Equal(t, 2, v6, "v6 refcount after second add")

	require.NoError(t, m.DeleteDNATRule(r1), "delete v6 dnat 1")
	v4, v6 = state.Counts()
	require.Equal(t, 0, v4, "v4 refcount unchanged")
	require.Equal(t, 1, v6, "v6 refcount after first delete")

	require.NoError(t, m.DeleteDNATRule(r2), "delete v6 dnat 2")
	v4, v6 = state.Counts()
	require.Equal(t, 0, v4)
	require.Equal(t, 0, v6, "v6 refcount after second delete")
}

// TestNftablesDNAT_DuplicateAddNoLeak verifies that a duplicate Add (same
// ForwardRule) does not double-increment the refcount.
func TestNftablesDNAT_DuplicateAddNoLeak(t *testing.T) {
	m := newNftRefcountManager(t, true)
	state := m.router.ipFwdState

	rule := dnatV4(8083)
	r1, err := m.AddDNATRule(rule)
	require.NoError(t, err, "add v4 dnat")
	v4, _ := state.Counts()
	require.Equal(t, 1, v4)

	// duplicate add: same rule ID, must be a no-op for the refcount.
	_, err = m.AddDNATRule(rule)
	require.NoError(t, err, "duplicate add")
	v4, _ = state.Counts()
	require.Equal(t, 1, v4, "duplicate add must not increment")

	require.NoError(t, m.DeleteDNATRule(r1), "delete v4 dnat")
	v4, _ = state.Counts()
	require.Equal(t, 0, v4, "single delete must drop to zero")
}

// TestNftablesDNAT_DeleteMissingNoUnderflow verifies deleting a rule that was
// never added does not underflow the refcount.
func TestNftablesDNAT_DeleteMissingNoUnderflow(t *testing.T) {
	m := newNftRefcountManager(t, true)
	state := m.router.ipFwdState

	// Construct a Rule reference for something never added. The router stores
	// rules by ID(), and DeleteDNATRule looks them up in r.rules; a missing
	// entry must be a no-op rather than calling Release.
	phantom := dnatV4(8099)
	require.NoError(t, m.DeleteDNATRule(&phantom), "delete missing v4 dnat")
	v4, v6 := state.Counts()
	require.Equal(t, 0, v4, "v4 refcount unaffected by missing delete")
	require.Equal(t, 0, v6, "v6 refcount unaffected")

	phantom6 := dnatV6(9099)
	require.NoError(t, m.DeleteDNATRule(&phantom6), "delete missing v6 dnat")
	v4, v6 = state.Counts()
	require.Equal(t, 0, v4)
	require.Equal(t, 0, v6, "v6 refcount unaffected by missing delete")

	// And after a phantom delete, a real add still results in count=1.
	r1, err := m.AddDNATRule(dnatV4(8100))
	require.NoError(t, err, "add v4 dnat after phantom delete")
	v4, _ = state.Counts()
	require.Equal(t, 1, v4, "real add still increments after phantom delete")
	require.NoError(t, m.DeleteDNATRule(r1))
}

// TestNftablesDNAT_DoubleDeleteNoUnderflow verifies that deleting the same rule
// twice does not underflow the refcount (the second delete is a no-op).
func TestNftablesDNAT_DoubleDeleteNoUnderflow(t *testing.T) {
	m := newNftRefcountManager(t, true)
	state := m.router.ipFwdState

	r1, err := m.AddDNATRule(dnatV6(9093))
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
