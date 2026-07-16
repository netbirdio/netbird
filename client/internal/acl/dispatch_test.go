package acl

import (
	"net/netip"
	"sync"
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
)

// TestNetworkZeroPrefixIsRoute guards the route-vs-peer dispatch
// invariant: the backends classify a rule as a peer rule purely by the
// absence of a destination (neither prefix nor set). A default route
// (0.0.0.0/0 or ::/0) is a valid prefix and must therefore classify as
// a route, not collapse into the peer path.
func TestNetworkZeroPrefixIsRoute(t *testing.T) {
	for _, p := range []string{"0.0.0.0/0", "::/0", "10.0.0.0/8"} {
		n := fwmgr.Network{Prefix: netip.MustParsePrefix(p)}
		assert.True(t, n.IsPrefix(), "%s must report IsPrefix", p)
		assert.True(t, n.IsPrefix() || n.IsSet(), "%s must classify as a route", p)
	}

	// A zero-value Network is the only peer-rule shape.
	var empty fwmgr.Network
	assert.False(t, empty.IsPrefix(), "zero Network must not be a prefix")
	assert.False(t, empty.IsSet(), "zero Network must not be a set")
}

// TestDetermineDestinationAlwaysRoute verifies determineDestination
// never yields an empty Network for a valid route rule: every branch
// (static prefix, default route, dynamic with/without domains, with and
// without a local resolver) produces a destination that classifies as a
// route. If this regresses, a route rule would be dispatched down the
// peer path, which matches on source only.
func TestDetermineDestinationAlwaysRoute(t *testing.T) {
	v4 := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
	v6 := []netip.Prefix{netip.MustParsePrefix("2001:db8::/48")}

	cases := []struct {
		name     string
		rule     *mgmProto.RouteFirewallRule
		resolver bool
		sources  []netip.Prefix
	}{
		{"static prefix", &mgmProto.RouteFirewallRule{Destination: "192.168.0.0/16"}, false, v4},
		{"static default route", &mgmProto.RouteFirewallRule{Destination: "0.0.0.0/0"}, false, v4},
		{"dynamic with domains + resolver", &mgmProto.RouteFirewallRule{IsDynamic: true, Domains: []string{"example.com"}}, true, v4},
		{"dynamic no domains + resolver (v4)", &mgmProto.RouteFirewallRule{IsDynamic: true}, true, v4},
		{"dynamic no domains + resolver (v6)", &mgmProto.RouteFirewallRule{IsDynamic: true}, true, v6},
		{"dynamic + no local resolver (v4)", &mgmProto.RouteFirewallRule{IsDynamic: true}, false, v4},
		{"dynamic + no local resolver (v6)", &mgmProto.RouteFirewallRule{IsDynamic: true}, false, v6},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest, err := determineDestination(tc.rule, tc.resolver, tc.sources)
			require.NoError(t, err)
			assert.True(t, dest.IsPrefix() || dest.IsSet(),
				"destination must classify as a route, got empty Network")
		})
	}
}

// countingFirewall wraps a real firewall.Manager and counts filter-rule
// add/delete calls so a test can assert how many backing rules the acl
// manager actually creates and tears down.
type countingFirewall struct {
	fwmgr.Manager
	mu       sync.Mutex
	addCalls int
	dels     int
	ruleIDs  map[fwmgr.RuleID]struct{}
}

// distinctRules returns the number of distinct backing rules the
// backend produced. Because the backend dedups identical content,
// repeated AddFilterRule calls for the same rule resolve to one id.
func (f *countingFirewall) distinctRules() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ruleIDs)
}

func (f *countingFirewall) AddFilterRule(id []byte, sources []netip.Prefix, destination fwmgr.Network, proto fwmgr.Protocol, sPort, dPort *fwmgr.Port, action fwmgr.Action) (fwmgr.Rule, error) {
	rule, err := f.Manager.AddFilterRule(id, sources, destination, proto, sPort, dPort, action)
	if err == nil {
		f.mu.Lock()
		f.addCalls++
		if f.ruleIDs == nil {
			f.ruleIDs = make(map[fwmgr.RuleID]struct{})
		}
		if rule != nil {
			f.ruleIDs[rule.ID()] = struct{}{}
		}
		f.mu.Unlock()
	}
	return rule, err
}

func (f *countingFirewall) DeleteFilterRule(r fwmgr.Rule) error {
	err := f.Manager.DeleteFilterRule(r)
	if err == nil {
		f.mu.Lock()
		f.dels++
		delete(f.ruleIDs, r.ID())
		f.mu.Unlock()
	}
	return err
}

func newCountingACL(t *testing.T) (*DefaultManager, *countingFirewall, func()) {
	t.Helper()
	t.Setenv("NB_WG_KERNEL_DISABLED", "true")
	t.Setenv(firewall.EnvForceUserspaceFirewall, "true")

	ctrl := gomock.NewController(t)
	ifaceMock := mocks.NewMockIFaceMapper(ctrl)
	ifaceMock.EXPECT().IsUserspaceBind().Return(true).AnyTimes()
	ifaceMock.EXPECT().SetFilter(gomock.Any())
	network := netip.MustParsePrefix("172.0.0.1/32")
	ifaceMock.EXPECT().Name().Return("lo").AnyTimes()
	ifaceMock.EXPECT().Address().Return(wgaddr.Address{IP: network.Addr(), Network: network}).AnyTimes()
	ifaceMock.EXPECT().GetWGDevice().Return(nil).AnyTimes()

	realFW, err := firewall.NewFirewall(ifaceMock, nil, flowLogger, false, iface.DefaultMTU)
	require.NoError(t, err)

	fw := &countingFirewall{Manager: realFW}
	cleanup := func() {
		require.NoError(t, realFW.Close(nil))
		ctrl.Finish()
	}
	return NewDefaultManager(fw), fw, cleanup
}

// TestDuplicateContentPoliciesShareOneRule verifies the dedup contract
// the backends rely on: two policies that authorize an identical flow
// (same selector and sources) collapse to a single backing firewall
// rule, and that rule survives until BOTH policies are gone. This is
// why the backend can dedup on add without refcounting on delete: the
// acl manager's pair key matches the backend's content key, so add and
// delete stay balanced per content key across full-state reapplies.
func TestDuplicateContentPoliciesShareOneRule(t *testing.T) {
	acl, fw, cleanup := newCountingACL(t)
	defer cleanup()

	ruleA := &mgmProto.FirewallRule{
		PolicyID:  []byte("policy-A"),
		PeerIP:    "10.0.0.1",
		Direction: mgmProto.RuleDirection_IN,
		Action:    mgmProto.RuleAction_ACCEPT,
		Protocol:  mgmProto.RuleProtocol_TCP,
		Port:      "443",
	}
	ruleB := &mgmProto.FirewallRule{
		PolicyID:  []byte("policy-B"),
		PeerIP:    "10.0.0.1",
		Direction: mgmProto.RuleDirection_IN,
		Action:    mgmProto.RuleAction_ACCEPT,
		Protocol:  mgmProto.RuleProtocol_TCP,
		Port:      "443",
	}

	// Both policies present: identical content collapses to one rule.
	acl.ApplyFiltering(&mgmProto.NetworkMap{FirewallRules: []*mgmProto.FirewallRule{ruleA, ruleB}, FirewallRulesIsEmpty: false}, false)
	assert.Equal(t, 1, fw.distinctRules(), "identical-content policies must produce one backing rule")
	assert.Equal(t, 1, len(acl.peerRulesPairs), "one content key, one pair")

	// Drop policy A only: the shared rule is still authorized by B, so
	// nothing is deleted.
	acl.ApplyFiltering(&mgmProto.NetworkMap{FirewallRules: []*mgmProto.FirewallRule{ruleB}, FirewallRulesIsEmpty: false}, false)
	assert.Equal(t, 1, fw.distinctRules(), "no new backing rule on reapply")
	assert.Equal(t, 0, fw.dels, "rule must survive while any policy still authorizes it")
	assert.Equal(t, 1, len(acl.peerRulesPairs))

	// Drop policy B too: now the content key has no authorizer and the
	// single backing rule is removed exactly once.
	acl.ApplyFiltering(&mgmProto.NetworkMap{FirewallRules: nil, FirewallRulesIsEmpty: true}, false)
	assert.Equal(t, 1, fw.dels, "rule removed once when last policy is gone")
	assert.Equal(t, 0, len(acl.peerRulesPairs))
}
