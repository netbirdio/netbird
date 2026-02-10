package uspfilter

import (
	"net/netip"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	wgdevice "golang.zx2c4.com/wireguard/device"

	fw "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/device"
	"github.com/netbirdio/netbird/client/iface/mocks"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
)

// TestAddRouteFilteringReturnsExistingRule verifies that adding the same route
// filtering rule twice returns the same rule ID (idempotent behavior).
func TestAddRouteFilteringReturnsExistingRule(t *testing.T) {
	manager := setupTestManager(t)

	sources := []netip.Prefix{
		netip.MustParsePrefix("100.64.1.0/24"),
		netip.MustParsePrefix("100.64.2.0/24"),
	}
	destination := fw.Network{Prefix: netip.MustParsePrefix("192.168.1.0/24")}

	// Add rule first time
	rule1, err := manager.AddRouteFiltering(
		[]byte("policy-1"),
		sources,
		destination,
		fw.ProtocolTCP,
		nil,
		&fw.Port{Values: []uint16{443}},
		fw.ActionAccept,
	)
	require.NoError(t, err)
	require.NotNil(t, rule1)

	// Add the same rule again
	rule2, err := manager.AddRouteFiltering(
		[]byte("policy-1"),
		sources,
		destination,
		fw.ProtocolTCP,
		nil,
		&fw.Port{Values: []uint16{443}},
		fw.ActionAccept,
	)
	require.NoError(t, err)
	require.NotNil(t, rule2)

	// These should be the same (idempotent) like nftables/iptables implementations
	assert.Equal(t, rule1.ID(), rule2.ID(),
		"Adding the same rule twice should return the same rule ID (idempotent)")

	manager.mutex.RLock()
	ruleCount := len(manager.routeRules)
	manager.mutex.RUnlock()

	assert.Equal(t, 2, ruleCount,
		"Should have exactly 2 rules (1 user rule + 1 block rule)")
}

// TestAddRouteFilteringDifferentRulesGetDifferentIDs verifies that rules with
// different parameters get distinct IDs.
func TestAddRouteFilteringDifferentRulesGetDifferentIDs(t *testing.T) {
	manager := setupTestManager(t)

	sources := []netip.Prefix{netip.MustParsePrefix("100.64.1.0/24")}

	// Add first rule
	rule1, err := manager.AddRouteFiltering(
		[]byte("policy-1"),
		sources,
		fw.Network{Prefix: netip.MustParsePrefix("192.168.1.0/24")},
		fw.ProtocolTCP,
		nil,
		&fw.Port{Values: []uint16{443}},
		fw.ActionAccept,
	)
	require.NoError(t, err)

	// Add different rule (different destination)
	rule2, err := manager.AddRouteFiltering(
		[]byte("policy-2"),
		sources,
		fw.Network{Prefix: netip.MustParsePrefix("192.168.2.0/24")}, // Different!
		fw.ProtocolTCP,
		nil,
		&fw.Port{Values: []uint16{443}},
		fw.ActionAccept,
	)
	require.NoError(t, err)

	assert.NotEqual(t, rule1.ID(), rule2.ID(),
		"Different rules should have different IDs")

	manager.mutex.RLock()
	ruleCount := len(manager.routeRules)
	manager.mutex.RUnlock()

	assert.Equal(t, 3, ruleCount, "Should have 3 rules (2 user rules + 1 block rule)")
}

// TestRouteRuleUpdateDoesNotCauseGap verifies that re-adding the same route
// rule during a network map update does not disrupt existing traffic.
func TestRouteRuleUpdateDoesNotCauseGap(t *testing.T) {
	manager := setupTestManager(t)

	sources := []netip.Prefix{netip.MustParsePrefix("100.64.1.0/24")}
	destination := fw.Network{Prefix: netip.MustParsePrefix("192.168.1.0/24")}

	rule1, err := manager.AddRouteFiltering(
		[]byte("policy-1"),
		sources,
		destination,
		fw.ProtocolTCP,
		nil,
		nil,
		fw.ActionAccept,
	)
	require.NoError(t, err)

	srcIP := netip.MustParseAddr("100.64.1.5")
	dstIP := netip.MustParseAddr("192.168.1.10")
	_, pass := manager.routeACLsPass(srcIP, dstIP, layers.LayerTypeTCP, 12345, 443)
	require.True(t, pass, "Traffic should pass with rule in place")

	// Re-add same rule (simulates network map update)
	rule2, err := manager.AddRouteFiltering(
		[]byte("policy-1"),
		sources,
		destination,
		fw.ProtocolTCP,
		nil,
		nil,
		fw.ActionAccept,
	)
	require.NoError(t, err)

	// Idempotent IDs mean rule1.ID() == rule2.ID(), so the ACL manager
	// won't delete rule1 during cleanup. If IDs differed, deleting rule1
	// would remove the only matching rule and cause a traffic gap.
	if rule1.ID() != rule2.ID() {
		err = manager.DeleteRouteRule(rule1)
		require.NoError(t, err)
	}

	_, passAfter := manager.routeACLsPass(srcIP, dstIP, layers.LayerTypeTCP, 12345, 443)
	assert.True(t, passAfter,
		"Traffic should still pass after rule update - no gap should occur")
}

// TestBlockInvalidRoutedIdempotent verifies that blockInvalidRouted creates
// exactly one drop rule for the WireGuard network prefix, and calling it again
// returns the same rule without duplicating.
func TestBlockInvalidRoutedIdempotent(t *testing.T) {
	ctrl := gomock.NewController(t)
	dev := mocks.NewMockDevice(ctrl)
	dev.EXPECT().MTU().Return(1500, nil).AnyTimes()

	wgNet := netip.MustParsePrefix("100.64.0.1/16")

	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      wgNet.Addr(),
				Network: wgNet,
			}
		},
		GetDeviceFunc: func() *device.FilteredDevice {
			return &device.FilteredDevice{Device: dev}
		},
		GetWGDeviceFunc: func() *wgdevice.Device {
			return &wgdevice.Device{}
		},
	}

	manager, err := Create(ifaceMock, false, flowLogger, iface.DefaultMTU)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil))
	})

	// Call blockInvalidRouted directly multiple times
	rule1, err := manager.blockInvalidRouted(ifaceMock)
	require.NoError(t, err)
	require.NotNil(t, rule1)

	rule2, err := manager.blockInvalidRouted(ifaceMock)
	require.NoError(t, err)
	require.NotNil(t, rule2)

	rule3, err := manager.blockInvalidRouted(ifaceMock)
	require.NoError(t, err)
	require.NotNil(t, rule3)

	// All should return the same rule
	assert.Equal(t, rule1.ID(), rule2.ID(), "Second call should return same rule")
	assert.Equal(t, rule2.ID(), rule3.ID(), "Third call should return same rule")

	// Should have exactly 1 route rule
	manager.mutex.RLock()
	ruleCount := len(manager.routeRules)
	manager.mutex.RUnlock()

	assert.Equal(t, 1, ruleCount, "Should have exactly 1 block rule after 3 calls")

	// Verify the rule blocks traffic to the WG network
	srcIP := netip.MustParseAddr("10.0.0.1")
	dstIP := netip.MustParseAddr("100.64.0.50")
	_, pass := manager.routeACLsPass(srcIP, dstIP, layers.LayerTypeTCP, 12345, 80)
	assert.False(t, pass, "Block rule should deny traffic to WG prefix")
}

// TestBlockRuleNotAccumulatedOnRepeatedEnableRouting verifies that calling
// EnableRouting multiple times (as happens on each route update) does not
// accumulate duplicate block rules in the routeRules slice.
func TestBlockRuleNotAccumulatedOnRepeatedEnableRouting(t *testing.T) {
	ctrl := gomock.NewController(t)
	dev := mocks.NewMockDevice(ctrl)
	dev.EXPECT().MTU().Return(1500, nil).AnyTimes()

	wgNet := netip.MustParsePrefix("100.64.0.1/16")

	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      wgNet.Addr(),
				Network: wgNet,
			}
		},
		GetDeviceFunc: func() *device.FilteredDevice {
			return &device.FilteredDevice{Device: dev}
		},
		GetWGDeviceFunc: func() *wgdevice.Device {
			return &wgdevice.Device{}
		},
	}

	manager, err := Create(ifaceMock, false, flowLogger, iface.DefaultMTU)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil))
	})

	// Call EnableRouting multiple times (simulating repeated route updates)
	for i := 0; i < 5; i++ {
		require.NoError(t, manager.EnableRouting())
	}

	manager.mutex.RLock()
	ruleCount := len(manager.routeRules)
	manager.mutex.RUnlock()

	assert.Equal(t, 1, ruleCount,
		"Repeated EnableRouting should not accumulate block rules")
}

// TestRouteRuleCountStableAcrossUpdates verifies that adding the same route
// rule multiple times does not create duplicate entries.
func TestRouteRuleCountStableAcrossUpdates(t *testing.T) {
	manager := setupTestManager(t)

	sources := []netip.Prefix{netip.MustParsePrefix("100.64.1.0/24")}
	destination := fw.Network{Prefix: netip.MustParsePrefix("192.168.1.0/24")}

	// Simulate 5 network map updates with the same route rule
	for i := 0; i < 5; i++ {
		rule, err := manager.AddRouteFiltering(
			[]byte("policy-1"),
			sources,
			destination,
			fw.ProtocolTCP,
			nil,
			&fw.Port{Values: []uint16{443}},
			fw.ActionAccept,
		)
		require.NoError(t, err)
		require.NotNil(t, rule)
	}

	manager.mutex.RLock()
	ruleCount := len(manager.routeRules)
	manager.mutex.RUnlock()

	assert.Equal(t, 2, ruleCount,
		"Should have exactly 2 rules (1 user rule + 1 block rule) after 5 updates")
}

// TestDeleteRouteRuleAfterIdempotentAdd verifies that deleting a route rule
// after adding it multiple times works correctly.
func TestDeleteRouteRuleAfterIdempotentAdd(t *testing.T) {
	manager := setupTestManager(t)

	sources := []netip.Prefix{netip.MustParsePrefix("100.64.1.0/24")}
	destination := fw.Network{Prefix: netip.MustParsePrefix("192.168.1.0/24")}

	// Add same rule twice
	rule1, err := manager.AddRouteFiltering(
		[]byte("policy-1"),
		sources,
		destination,
		fw.ProtocolTCP,
		nil,
		nil,
		fw.ActionAccept,
	)
	require.NoError(t, err)

	rule2, err := manager.AddRouteFiltering(
		[]byte("policy-1"),
		sources,
		destination,
		fw.ProtocolTCP,
		nil,
		nil,
		fw.ActionAccept,
	)
	require.NoError(t, err)

	require.Equal(t, rule1.ID(), rule2.ID(), "Should return same rule ID")

	// Delete using first reference
	err = manager.DeleteRouteRule(rule1)
	require.NoError(t, err)

	// Verify traffic no longer passes
	srcIP := netip.MustParseAddr("100.64.1.5")
	dstIP := netip.MustParseAddr("192.168.1.10")
	_, pass := manager.routeACLsPass(srcIP, dstIP, layers.LayerTypeTCP, 12345, 443)
	assert.False(t, pass, "Traffic should not pass after rule deletion")
}

func setupTestManager(t *testing.T) *Manager {
	t.Helper()

	ctrl := gomock.NewController(t)
	dev := mocks.NewMockDevice(ctrl)
	dev.EXPECT().MTU().Return(1500, nil).AnyTimes()

	wgNet := netip.MustParsePrefix("100.64.0.1/16")

	ifaceMock := &IFaceMock{
		SetFilterFunc: func(device.PacketFilter) error { return nil },
		AddressFunc: func() wgaddr.Address {
			return wgaddr.Address{
				IP:      wgNet.Addr(),
				Network: wgNet,
			}
		},
		GetDeviceFunc: func() *device.FilteredDevice {
			return &device.FilteredDevice{Device: dev}
		},
		GetWGDeviceFunc: func() *wgdevice.Device {
			return &wgdevice.Device{}
		},
	}

	manager, err := Create(ifaceMock, false, flowLogger, iface.DefaultMTU)
	require.NoError(t, err)
	require.NoError(t, manager.EnableRouting())

	t.Cleanup(func() {
		require.NoError(t, manager.Close(nil))
	})

	return manager
}
