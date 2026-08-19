package acl

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/acl/mocks"
	"github.com/netbirdio/netbird/client/internal/netflow"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

var flowLogger = netflow.NewManager(nil, []byte{}, nil).GetLogger()

func TestDefaultManager(t *testing.T) {
	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	t.Setenv(firewall.EnvForceUserspaceFirewall, "true")

	networkMap := &mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_TCP,
				Port:      "80",
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_DROP,
				Protocol:  mgmProto.RuleProtocol_UDP,
				Port:      "53",
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ifaceMock := mocks.NewMockIFaceMapper(ctrl)
	ifaceMock.EXPECT().IsUserspaceBind().Return(true).AnyTimes()
	ifaceMock.EXPECT().SetFilter(gomock.Any())
	network := netip.MustParsePrefix("172.0.0.1/32")

	ifaceMock.EXPECT().Name().Return("lo").AnyTimes()
	ifaceMock.EXPECT().Address().Return(wgaddr.Address{
		IP:      network.Addr(),
		Network: network,
	}).AnyTimes()
	ifaceMock.EXPECT().GetWGDevice().Return(nil).AnyTimes()

	fw, err := firewall.NewFirewall(ifaceMock, nil, flowLogger, false, iface.DefaultMTU)
	require.NoError(t, err)
	defer func() {
		err = fw.Close(nil)
		require.NoError(t, err)
	}()

	acl := NewDefaultManager(fw)

	t.Run("apply firewall rules", func(t *testing.T) {
		acl.ApplyFiltering(networkMap, false)

		if fw.IsStateful() {
			assert.Equal(t, 0, len(acl.peerRulesPairs))
		} else {
			assert.Equal(t, 2, len(acl.peerRulesPairs))
		}
	})

	t.Run("add extra rules", func(t *testing.T) {
		existedPairs := map[string]struct{}{}
		for id := range acl.peerRulesPairs {
			existedPairs[id.ID()] = struct{}{}
		}

		// remove first rule
		networkMap.FirewallRules = networkMap.FirewallRules[1:]
		networkMap.FirewallRules = append(
			networkMap.FirewallRules,
			&mgmProto.FirewallRule{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_DROP,
				Protocol:  mgmProto.RuleProtocol_ICMP,
			},
		)

		acl.ApplyFiltering(networkMap, false)

		expectedRules := 2
		if fw.IsStateful() {
			expectedRules = 1 // only the inbound rule
		}

		assert.Equal(t, expectedRules, len(acl.peerRulesPairs))

		// check that old rule was removed
		previousCount := 0
		for id := range acl.peerRulesPairs {
			if _, ok := existedPairs[id.ID()]; ok {
				previousCount++
			}
		}

		expectedPreviousCount := 0
		if !fw.IsStateful() {
			expectedPreviousCount = 1
		}
		assert.Equal(t, expectedPreviousCount, previousCount)
	})

	t.Run("handle default rules", func(t *testing.T) {
		networkMap.FirewallRules = networkMap.FirewallRules[:0]

		networkMap.FirewallRulesIsEmpty = true
		acl.ApplyFiltering(networkMap, false)
		assert.Equal(t, 0, len(acl.peerRulesPairs))

		networkMap.FirewallRulesIsEmpty = false
		acl.ApplyFiltering(networkMap, false)

		expectedRules := 1
		if fw.IsStateful() {
			expectedRules = 1 // only inbound allow-all rule
		}
		assert.Equal(t, expectedRules, len(acl.peerRulesPairs))
	})
}

func TestDefaultManagerStateless(t *testing.T) {
	// stateless currently only in userspace, so we have to disable kernel
	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	t.Setenv(firewall.EnvForceUserspaceFirewall, "true")
	t.Setenv("NB_DISABLE_CONNTRACK", "true")

	networkMap := &mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_OUT,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_TCP,
				Port:      "80",
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_UDP,
				Port:      "53",
			},
		},
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ifaceMock := mocks.NewMockIFaceMapper(ctrl)
	ifaceMock.EXPECT().IsUserspaceBind().Return(true).AnyTimes()
	ifaceMock.EXPECT().SetFilter(gomock.Any())
	network := netip.MustParsePrefix("172.0.0.1/32")

	ifaceMock.EXPECT().Name().Return("lo").AnyTimes()
	ifaceMock.EXPECT().Address().Return(wgaddr.Address{
		IP:      network.Addr(),
		Network: network,
	}).AnyTimes()
	ifaceMock.EXPECT().GetWGDevice().Return(nil).AnyTimes()

	fw, err := firewall.NewFirewall(ifaceMock, nil, flowLogger, false, iface.DefaultMTU)
	require.NoError(t, err)
	defer func() {
		err = fw.Close(nil)
		require.NoError(t, err)
	}()

	acl := NewDefaultManager(fw)

	t.Run("stateless firewall creates outbound rules", func(t *testing.T) {
		acl.ApplyFiltering(networkMap, false)

		// In stateless mode, we should have both inbound and outbound rules
		assert.False(t, fw.IsStateful())
		assert.Equal(t, 2, len(acl.peerRulesPairs))
	})
}

// TestDenyRulesNotAccumulatedOnRepeatedApply verifies that applying the same
// deny rules repeatedly does not accumulate duplicate rules in the uspfilter.
// This tests the full ACL manager -> uspfilter integration.
func TestDenyRulesNotAccumulatedOnRepeatedApply(t *testing.T) {
	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	t.Setenv(firewall.EnvForceUserspaceFirewall, "true")

	networkMap := &mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_DROP,
				Protocol:  mgmProto.RuleProtocol_TCP,
				Port:      "22",
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_DROP,
				Protocol:  mgmProto.RuleProtocol_TCP,
				Port:      "80",
			},
			{
				PeerIP:    "10.93.0.3",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_TCP,
				Port:      "443",
			},
		},
		FirewallRulesIsEmpty: false,
	}

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ifaceMock := mocks.NewMockIFaceMapper(ctrl)
	ifaceMock.EXPECT().IsUserspaceBind().Return(true).AnyTimes()
	ifaceMock.EXPECT().SetFilter(gomock.Any())
	network := netip.MustParsePrefix("172.0.0.1/32")
	ifaceMock.EXPECT().Name().Return("lo").AnyTimes()
	ifaceMock.EXPECT().Address().Return(wgaddr.Address{
		IP:      network.Addr(),
		Network: network,
	}).AnyTimes()
	ifaceMock.EXPECT().GetWGDevice().Return(nil).AnyTimes()

	fw, err := firewall.NewFirewall(ifaceMock, nil, flowLogger, false, iface.DefaultMTU)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, fw.Close(nil))
	}()

	acl := NewDefaultManager(fw)

	// Apply the same rules 5 times (simulating repeated network map updates)
	for i := 0; i < 5; i++ {
		acl.ApplyFiltering(networkMap, false)
	}

	// The ACL manager should track exactly 3 rule pairs (2 deny + 1 accept inbound)
	assert.Equal(t, 3, len(acl.peerRulesPairs),
		"Should have exactly 3 rule pairs after 5 identical updates")
}

// TestDenyRulesCleanedUpOnRemoval verifies that deny rules are properly cleaned
// up when they're removed from the network map in a subsequent update.
func TestDenyRulesCleanedUpOnRemoval(t *testing.T) {
	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	t.Setenv(firewall.EnvForceUserspaceFirewall, "true")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ifaceMock := mocks.NewMockIFaceMapper(ctrl)
	ifaceMock.EXPECT().IsUserspaceBind().Return(true).AnyTimes()
	ifaceMock.EXPECT().SetFilter(gomock.Any())
	network := netip.MustParsePrefix("172.0.0.1/32")
	ifaceMock.EXPECT().Name().Return("lo").AnyTimes()
	ifaceMock.EXPECT().Address().Return(wgaddr.Address{
		IP:      network.Addr(),
		Network: network,
	}).AnyTimes()
	ifaceMock.EXPECT().GetWGDevice().Return(nil).AnyTimes()

	fw, err := firewall.NewFirewall(ifaceMock, nil, flowLogger, false, iface.DefaultMTU)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, fw.Close(nil))
	}()

	acl := NewDefaultManager(fw)

	// First update: add deny and accept rules
	networkMap1 := &mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_DROP,
				Protocol:  mgmProto.RuleProtocol_TCP,
				Port:      "22",
			},
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_TCP,
				Port:      "443",
			},
		},
		FirewallRulesIsEmpty: false,
	}

	acl.ApplyFiltering(networkMap1, false)
	assert.Equal(t, 2, len(acl.peerRulesPairs), "Should have 2 rules after first update")

	// Second update: remove the deny rule, keep only accept
	networkMap2 := &mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PeerIP:    "10.93.0.2",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_TCP,
				Port:      "443",
			},
		},
		FirewallRulesIsEmpty: false,
	}

	acl.ApplyFiltering(networkMap2, false)
	assert.Equal(t, 1, len(acl.peerRulesPairs),
		"Should have 1 rule after removing deny rule")

	// Third update: remove all rules
	networkMap3 := &mgmProto.NetworkMap{
		FirewallRules:        []*mgmProto.FirewallRule{},
		FirewallRulesIsEmpty: true,
	}

	acl.ApplyFiltering(networkMap3, false)
	assert.Equal(t, 0, len(acl.peerRulesPairs),
		"Should have 0 rules after removing all rules")
}

// TestRuleUpdateChangingAction verifies that when a rule's action changes from
// accept to deny (or vice versa), the old rule is properly removed and the new
// one added without leaking.
func TestRuleUpdateChangingAction(t *testing.T) {
	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	t.Setenv(firewall.EnvForceUserspaceFirewall, "true")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ifaceMock := mocks.NewMockIFaceMapper(ctrl)
	ifaceMock.EXPECT().IsUserspaceBind().Return(true).AnyTimes()
	ifaceMock.EXPECT().SetFilter(gomock.Any())
	network := netip.MustParsePrefix("172.0.0.1/32")
	ifaceMock.EXPECT().Name().Return("lo").AnyTimes()
	ifaceMock.EXPECT().Address().Return(wgaddr.Address{
		IP:      network.Addr(),
		Network: network,
	}).AnyTimes()
	ifaceMock.EXPECT().GetWGDevice().Return(nil).AnyTimes()

	fw, err := firewall.NewFirewall(ifaceMock, nil, flowLogger, false, iface.DefaultMTU)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, fw.Close(nil))
	}()

	acl := NewDefaultManager(fw)

	// First update: accept rule
	networkMap := &mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_TCP,
				Port:      "22",
			},
		},
		FirewallRulesIsEmpty: false,
	}
	acl.ApplyFiltering(networkMap, false)
	assert.Equal(t, 1, len(acl.peerRulesPairs))

	// Second update: change to deny (same IP/port/proto, different action)
	networkMap.FirewallRules = []*mgmProto.FirewallRule{
		{
			PeerIP:    "10.93.0.1",
			Direction: mgmProto.RuleDirection_IN,
			Action:    mgmProto.RuleAction_DROP,
			Protocol:  mgmProto.RuleProtocol_TCP,
			Port:      "22",
		},
	}
	acl.ApplyFiltering(networkMap, false)

	// Should still have exactly 1 rule (the old accept removed, new deny added)
	assert.Equal(t, 1, len(acl.peerRulesPairs),
		"Changing action should result in exactly 1 rule, not 2")
}

func TestPortInfoEmpty(t *testing.T) {
	tests := []struct {
		name     string
		portInfo *mgmProto.PortInfo
		expected bool
	}{
		{
			name:     "nil PortInfo should be empty",
			portInfo: nil,
			expected: true,
		},
		{
			name: "PortInfo with zero port should be empty",
			portInfo: &mgmProto.PortInfo{
				PortSelection: &mgmProto.PortInfo_Port{
					Port: 0,
				},
			},
			expected: true,
		},
		{
			name: "PortInfo with valid port should not be empty",
			portInfo: &mgmProto.PortInfo{
				PortSelection: &mgmProto.PortInfo_Port{
					Port: 80,
				},
			},
			expected: false,
		},
		{
			name: "PortInfo with nil range should be empty",
			portInfo: &mgmProto.PortInfo{
				PortSelection: &mgmProto.PortInfo_Range_{
					Range: nil,
				},
			},
			expected: true,
		},
		{
			name: "PortInfo with zero start range should be empty",
			portInfo: &mgmProto.PortInfo{
				PortSelection: &mgmProto.PortInfo_Range_{
					Range: &mgmProto.PortInfo_Range{
						Start: 0,
						End:   100,
					},
				},
			},
			expected: true,
		},
		{
			name: "PortInfo with zero end range should be empty",
			portInfo: &mgmProto.PortInfo{
				PortSelection: &mgmProto.PortInfo_Range_{
					Range: &mgmProto.PortInfo_Range{
						Start: 80,
						End:   0,
					},
				},
			},
			expected: true,
		},
		{
			name: "PortInfo with valid range should not be empty",
			portInfo: &mgmProto.PortInfo{
				PortSelection: &mgmProto.PortInfo_Range_{
					Range: &mgmProto.PortInfo_Range{
						Start: 8080,
						End:   8090,
					},
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := portInfoEmpty(tt.portInfo)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestApplyFilteringSkipsUnchangedConfig verifies that an identical network map
// re-applied is recognized as a no-op (hash unchanged), while a real change to
// any firewall-relevant input forces a re-apply (hash changes). This is the
// guard that prevents a full ruleset rebuild + flush on every redundant sync.
func TestApplyFilteringSkipsUnchangedConfig(t *testing.T) {
	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	t.Setenv(firewall.EnvForceUserspaceFirewall, "true")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ifaceMock := mocks.NewMockIFaceMapper(ctrl)
	ifaceMock.EXPECT().IsUserspaceBind().Return(true).AnyTimes()
	ifaceMock.EXPECT().SetFilter(gomock.Any())
	network := netip.MustParsePrefix("172.0.0.1/32")
	ifaceMock.EXPECT().Name().Return("lo").AnyTimes()
	ifaceMock.EXPECT().Address().Return(wgaddr.Address{
		IP:      network.Addr(),
		Network: network,
	}).AnyTimes()
	ifaceMock.EXPECT().GetWGDevice().Return(nil).AnyTimes()

	fw, err := firewall.NewFirewall(ifaceMock, nil, flowLogger, false, iface.DefaultMTU)
	require.NoError(t, err)
	defer func() {
		require.NoError(t, fw.Close(nil))
	}()

	acl := NewDefaultManager(fw)

	networkMap := &mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PeerIP:    "10.93.0.1",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_ACCEPT,
				Protocol:  mgmProto.RuleProtocol_TCP,
				Port:      "22",
			},
		},
		FirewallRulesIsEmpty: false,
	}

	acl.ApplyFiltering(networkMap, false)
	require.True(t, acl.hasAppliedConfig, "config should be marked applied after first apply")
	firstHash := acl.previousConfigHash
	require.NotZero(t, firstHash)

	// Re-applying the identical map must not change the recorded hash: the
	// expensive rebuild path was skipped.
	acl.ApplyFiltering(networkMap, false)
	assert.Equal(t, firstHash, acl.previousConfigHash,
		"identical re-apply must be a no-op (hash unchanged)")

	// A real change must produce a different hash and re-apply.
	networkMap.FirewallRules[0].Action = mgmProto.RuleAction_DROP
	acl.ApplyFiltering(networkMap, false)
	assert.NotEqual(t, firstHash, acl.previousConfigHash,
		"changing a rule's action must force a re-apply (hash changed)")

	// The dnsRouteFeatureFlag also participates in the hash.
	changedHash := acl.previousConfigHash
	acl.ApplyFiltering(networkMap, true)
	assert.NotEqual(t, changedHash, acl.previousConfigHash,
		"flipping dnsRouteFeatureFlag must force a re-apply (hash changed)")
}

func buildNetworkMap(peerRules, routeRules int) *mgmProto.NetworkMap {
	nm := &mgmProto.NetworkMap{
		FirewallRulesIsEmpty:      peerRules == 0,
		RoutesFirewallRulesIsEmpty: routeRules == 0,
	}
	for i := range peerRules {
		nm.FirewallRules = append(nm.FirewallRules, &mgmProto.FirewallRule{
			PeerIP:    fmt.Sprintf("10.%d.%d.%d", i>>16&0xff, i>>8&0xff, i&0xff),
			Direction: mgmProto.RuleDirection_IN,
			Action:    mgmProto.RuleAction_ACCEPT,
			Protocol:  mgmProto.RuleProtocol_TCP,
			Port:      fmt.Sprintf("%d", 1024+i%64511),
		})
	}
	for i := range routeRules {
		nm.RoutesFirewallRules = append(nm.RoutesFirewallRules, &mgmProto.RouteFirewallRule{
			Destination:  fmt.Sprintf("192.168.%d.0/24", i%256),
			SourceRanges: []string{fmt.Sprintf("10.0.%d.0/24", i%256)},
			Action:       mgmProto.RuleAction_ACCEPT,
			Protocol:     mgmProto.RuleProtocol_ALL,
		})
	}
	return nm
}

func BenchmarkFirewallConfigHash_Small(b *testing.B) {
	d := &DefaultManager{}
	nm := buildNetworkMap(10, 5)
	b.ResetTimer()
	for b.Loop() {
		_, _ = d.firewallConfigHash(nm, false)
	}
}

func BenchmarkFirewallConfigHash_Medium(b *testing.B) {
	d := &DefaultManager{}
	nm := buildNetworkMap(100, 50)
	b.ResetTimer()
	for b.Loop() {
		_, _ = d.firewallConfigHash(nm, false)
	}
}

func BenchmarkFirewallConfigHash_Large(b *testing.B) {
	d := &DefaultManager{}
	nm := buildNetworkMap(1000, 200)
	b.ResetTimer()
	for b.Loop() {
		_, _ = d.firewallConfigHash(nm, false)
	}
}

// TestFirewallConfigHashDeterministic verifies the hash is stable for equal
// inputs and order-independent for the rule slices (management does not
// guarantee rule order).
func TestFirewallConfigHashDeterministic(t *testing.T) {
	d := &DefaultManager{}

	nm1 := &mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			{PeerIP: "10.0.0.1", Direction: mgmProto.RuleDirection_IN, Action: mgmProto.RuleAction_ACCEPT, Protocol: mgmProto.RuleProtocol_TCP, Port: "22"},
			{PeerIP: "10.0.0.2", Direction: mgmProto.RuleDirection_IN, Action: mgmProto.RuleAction_DROP, Protocol: mgmProto.RuleProtocol_TCP, Port: "80"},
		},
	}
	// Same rules, reversed order.
	nm2 := &mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			nm1.FirewallRules[1],
			nm1.FirewallRules[0],
		},
	}

	h1, err := d.firewallConfigHash(nm1, false)
	require.NoError(t, err)
	h2, err := d.firewallConfigHash(nm2, false)
	require.NoError(t, err)
	assert.Equal(t, h1, h2, "hash must be order-independent for rule slices")
}
