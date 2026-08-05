package acl

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/client/firewall"
	fwmgr "github.com/netbirdio/netbird/client/firewall/manager"
	"github.com/netbirdio/netbird/client/iface"
	"github.com/netbirdio/netbird/client/iface/wgaddr"
	"github.com/netbirdio/netbird/client/internal/acl/mocks"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/netiputil"
)

// TestGroupPeerRulesPolicyIDSeparates verifies that two FirewallRules
// with identical selectors but different PolicyIDs do NOT get merged
// into one group, so each policy's sources merge under its own
// attribution id. (Identical-content groups may still dedup to one
// backing rule at the backend; see TestDuplicateContentPoliciesShareOneRule.)
func TestGroupPeerRulesPolicyIDSeparates(t *testing.T) {
	rules := []*mgmProto.FirewallRule{
		{
			PolicyID:  []byte("policy-A"),
			PeerIP:    "10.0.0.1",
			Direction: mgmProto.RuleDirection_IN,
			Action:    mgmProto.RuleAction_ACCEPT,
			Protocol:  mgmProto.RuleProtocol_TCP,
			Port:      "443",
		},
		{
			PolicyID:  []byte("policy-B"),
			PeerIP:    "10.0.0.1",
			Direction: mgmProto.RuleDirection_IN,
			Action:    mgmProto.RuleAction_ACCEPT,
			Protocol:  mgmProto.RuleProtocol_TCP,
			Port:      "443",
		},
	}

	groups, denyErr, err := groupPeerRules(rules)
	require.NoError(t, denyErr)
	require.NoError(t, err)
	require.Len(t, groups, 2, "rules with different PolicyIDs must produce separate groups")
}

// TestGroupPeerRulesFamilySeparates verifies that v4 and v6 rules
// belonging to the same policy don't merge.
func TestGroupPeerRulesFamilySeparates(t *testing.T) {
	rules := []*mgmProto.FirewallRule{
		{
			PolicyID:  []byte("policy-A"),
			PeerIP:    "10.0.0.1",
			Direction: mgmProto.RuleDirection_IN,
			Action:    mgmProto.RuleAction_ACCEPT,
			Protocol:  mgmProto.RuleProtocol_TCP,
			Port:      "443",
		},
		{
			PolicyID:  []byte("policy-A"),
			PeerIP:    "2001:db8::1",
			Direction: mgmProto.RuleDirection_IN,
			Action:    mgmProto.RuleAction_ACCEPT,
			Protocol:  mgmProto.RuleProtocol_TCP,
			Port:      "443",
		},
	}

	groups, denyErr, err := groupPeerRules(rules)
	require.NoError(t, denyErr)
	require.NoError(t, err)
	require.Len(t, groups, 2, "rules of different families must produce separate groups")

	var sawV4, sawV6 bool
	for _, g := range groups {
		require.Len(t, g.sources, 1)
		if g.sources[0].Addr().Is4() {
			sawV4 = true
		}
		if g.sources[0].Addr().Is6() {
			sawV6 = true
		}
	}
	assert.True(t, sawV4 && sawV6)
}

// TestGroupPeerRulesSplitsMixedFamilySingleRule verifies that a single
// FirewallRule carrying both v4 and v6 source prefixes is split into one
// group per family. Each backend keys a rule to a single family, so a
// group whose sources span families would mismatch the other family's
// sources. mgmt normally emits one rule per family; this guards against
// a mixed-family rule slipping through.
func TestGroupPeerRulesSplitsMixedFamilySingleRule(t *testing.T) {
	srcs := [][]byte{
		netiputil.EncodeAddr(netip.MustParseAddr("10.0.0.1")),
		netiputil.EncodeAddr(netip.MustParseAddr("2001:db8::1")),
		netiputil.EncodeAddr(netip.MustParseAddr("10.0.0.2")),
		netiputil.EncodeAddr(netip.MustParseAddr("2001:db8::2")),
	}
	rules := []*mgmProto.FirewallRule{
		{
			PolicyID:       []byte("policy-A"),
			SourcePrefixes: srcs,
			Direction:      mgmProto.RuleDirection_IN,
			Action:         mgmProto.RuleAction_ACCEPT,
			Protocol:       mgmProto.RuleProtocol_TCP,
			Port:           "443",
		},
	}

	groups, denyErr, err := groupPeerRules(rules)
	require.NoError(t, denyErr)
	require.NoError(t, err)
	require.Len(t, groups, 2, "mixed-family sources in one rule must split into two groups")

	for _, g := range groups {
		require.Len(t, g.sources, 2)
		v6 := prefixIsV6(g.sources[0])
		for _, s := range g.sources {
			assert.Equal(t, v6, prefixIsV6(s), "every source in a group must share one family")
		}
	}
}

// TestGroupPeerRulesMergesSameSelector verifies that rules sharing
// every distinguishing field (policy, family, direction, action,
// proto, port) collapse into a single multi-source group.
func TestGroupPeerRulesMergesSameSelector(t *testing.T) {
	mk := func(peerIP string) *mgmProto.FirewallRule {
		return &mgmProto.FirewallRule{
			PolicyID:  []byte("policy-A"),
			PeerIP:    peerIP,
			Direction: mgmProto.RuleDirection_IN,
			Action:    mgmProto.RuleAction_ACCEPT,
			Protocol:  mgmProto.RuleProtocol_TCP,
			Port:      "443",
		}
	}
	rules := []*mgmProto.FirewallRule{mk("10.0.0.1"), mk("10.0.0.2"), mk("10.0.0.3")}

	groups, denyErr, err := groupPeerRules(rules)
	require.NoError(t, denyErr)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Len(t, groups[0].sources, 3)
}

// TestGroupPeerRulesPortSeparates verifies that PortInfo is part of the
// selector key: rules differing only in port must not merge, and a
// single port must not merge with a range. A regression dropping the
// port from the key would collapse rules for different ports into one.
func TestGroupPeerRulesPortSeparates(t *testing.T) {
	mkPort := func(peerIP string, port uint32) *mgmProto.FirewallRule {
		return &mgmProto.FirewallRule{
			PolicyID:  []byte("policy-A"),
			PeerIP:    peerIP,
			Direction: mgmProto.RuleDirection_IN,
			Action:    mgmProto.RuleAction_ACCEPT,
			Protocol:  mgmProto.RuleProtocol_TCP,
			PortInfo:  &mgmProto.PortInfo{PortSelection: &mgmProto.PortInfo_Port{Port: port}},
		}
	}

	groups, denyErr, err := groupPeerRules([]*mgmProto.FirewallRule{
		mkPort("10.0.0.1", 80), mkPort("10.0.0.2", 80), mkPort("10.0.0.3", 443),
	})
	require.NoError(t, denyErr)
	require.NoError(t, err)
	require.Len(t, groups, 2, "rules on different ports must not merge")

	rangeRule := &mgmProto.FirewallRule{
		PolicyID:  []byte("policy-A"),
		PeerIP:    "10.0.0.4",
		Direction: mgmProto.RuleDirection_IN,
		Action:    mgmProto.RuleAction_ACCEPT,
		Protocol:  mgmProto.RuleProtocol_TCP,
		PortInfo:  &mgmProto.PortInfo{PortSelection: &mgmProto.PortInfo_Range_{Range: &mgmProto.PortInfo_Range{Start: 80, End: 90}}},
	}
	groups, denyErr, err = groupPeerRules([]*mgmProto.FirewallRule{mkPort("10.0.0.1", 80), rangeRule})
	require.NoError(t, denyErr)
	require.NoError(t, err)
	require.Len(t, groups, 2, "a single port and a range must not merge")
}

// TestGroupPeerRulesUsesSourcePrefixesWhenPresent verifies that the
// new sourcePrefixes wire field is consumed and produces a
// multi-source group in one shot (no client-side merging needed).
func TestGroupPeerRulesUsesSourcePrefixesWhenPresent(t *testing.T) {
	srcs := [][]byte{
		netiputil.EncodeAddr(netip.MustParseAddr("10.0.0.1")),
		netiputil.EncodeAddr(netip.MustParseAddr("10.0.0.2")),
		netiputil.EncodeAddr(netip.MustParseAddr("10.0.0.3")),
	}
	rules := []*mgmProto.FirewallRule{
		{
			PolicyID:       []byte("policy-A"),
			SourcePrefixes: srcs,
			Direction:      mgmProto.RuleDirection_IN,
			Action:         mgmProto.RuleAction_ACCEPT,
			Protocol:       mgmProto.RuleProtocol_TCP,
			Port:           "443",
		},
	}

	groups, denyErr, err := groupPeerRules(rules)
	require.NoError(t, denyErr)
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Len(t, groups[0].sources, 3)
}

// TestGroupPeerRulesActionSeparates verifies the obvious: accept
// and drop rules with the same selector don't merge.
func TestGroupPeerRulesActionSeparates(t *testing.T) {
	rules := []*mgmProto.FirewallRule{
		{
			PolicyID:  []byte("policy-A"),
			PeerIP:    "10.0.0.1",
			Direction: mgmProto.RuleDirection_IN,
			Action:    mgmProto.RuleAction_ACCEPT,
			Protocol:  mgmProto.RuleProtocol_TCP,
			Port:      "443",
		},
		{
			PolicyID:  []byte("policy-A"),
			PeerIP:    "10.0.0.1",
			Direction: mgmProto.RuleDirection_IN,
			Action:    mgmProto.RuleAction_DROP,
			Protocol:  mgmProto.RuleProtocol_TCP,
			Port:      "443",
		},
	}

	groups, denyErr, err := groupPeerRules(rules)
	require.NoError(t, denyErr)
	require.NoError(t, err)
	require.Len(t, groups, 2)
}

// failingDeleteFirewall wraps a real firewall.Manager and forces the
// next N DeleteFilterRule calls to fail. Used to verify that the acl
// manager retains rules whose deletion was rejected by the backend,
// so they get retried on the next ApplyFiltering pass instead of
// becoming orphans.
type failingDeleteFirewall struct {
	fwmgr.Manager
	failCount int
}

func (f *failingDeleteFirewall) DeleteFilterRule(r fwmgr.Rule) error {
	if f.failCount > 0 {
		f.failCount--
		return errors.New("simulated delete failure")
	}
	return f.Manager.DeleteFilterRule(r)
}

// TestApplyFilteringRetainsRulesOnDeleteFailure verifies that a
// transient DeleteFilterRule error doesn't make the acl manager
// forget about a rule. The rule must remain in peerRulesPairs so the
// next ApplyFiltering pass attempts the delete again.
func TestApplyFilteringRetainsRulesOnDeleteFailure(t *testing.T) {
	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	t.Setenv(firewall.EnvForceUserspaceFirewall, "true")

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	ifaceMock := mocks.NewMockIFaceMapper(ctrl)
	ifaceMock.EXPECT().IsUserspaceBind().Return(true).AnyTimes()
	ifaceMock.EXPECT().SetFilter(gomock.Any())
	network := netip.MustParsePrefix("172.0.0.1/32")
	ifaceMock.EXPECT().Name().Return("lo").AnyTimes()
	ifaceMock.EXPECT().Address().Return(wgaddr.Address{IP: network.Addr(), Network: network}).AnyTimes()
	ifaceMock.EXPECT().GetWGDevice().Return(nil).AnyTimes()

	realFW, err := firewall.NewFirewall(ifaceMock, nil, flowLogger, false, iface.DefaultMTU)
	require.NoError(t, err)
	defer func() { require.NoError(t, realFW.Close(nil)) }()

	fw := &failingDeleteFirewall{Manager: realFW}
	acl := NewDefaultManager(fw)

	// First pass: install a rule.
	netmap1 := &mgmProto.NetworkMap{
		FirewallRules: []*mgmProto.FirewallRule{
			{
				PolicyID:  []byte("policy-A"),
				PeerIP:    "10.0.0.1",
				Direction: mgmProto.RuleDirection_IN,
				Action:    mgmProto.RuleAction_DROP,
				Protocol:  mgmProto.RuleProtocol_TCP,
				Port:      "22",
			},
		},
		FirewallRulesIsEmpty: false,
	}
	acl.ApplyFiltering(netmap1, false)
	require.Equal(t, 1, len(acl.peerRulesPairs), "rule should be installed")

	// Second pass: remove the rule from the map. The backend will
	// fail the delete; the acl manager must retain the rule.
	fw.failCount = 1
	netmap2 := &mgmProto.NetworkMap{FirewallRules: nil, FirewallRulesIsEmpty: true}
	acl.ApplyFiltering(netmap2, false)
	require.Equal(t, 1, len(acl.peerRulesPairs),
		"rule must be retained when DeleteFilterRule fails so it gets retried")

	// Third pass: same map, backend no longer fails. The rule
	// should now succeed in being removed.
	acl.ApplyFiltering(netmap2, false)
	require.Equal(t, 0, len(acl.peerRulesPairs), "retry should succeed")
}
