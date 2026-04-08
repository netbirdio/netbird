package types

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/route"
)

func newTestBuilder() *NetworkMapBuilder {
	return &NetworkMapBuilder{
		cache: &NetworkMapCache{
			globalRouteRules: make(map[string]*RouteFirewallRule),
			noACGRoutes:      make(map[route.ID]*RouteOwnerInfo),
			acgToRoutes:      make(map[string]map[route.ID]*RouteOwnerInfo),
			peerRoutes:       make(map[string]*PeerRoutesView),
		},
	}
}

func TestUpdateRouteFirewallRules_FamilyMatching(t *testing.T) {
	b := newTestBuilder()

	// Simulate a dynamic route with both v4 and v6 rules sharing the same RouteID.
	b.cache.globalRouteRules["rule-v4"] = &RouteFirewallRule{
		RouteID:      "route-dynamic",
		SourceRanges: []string{"100.64.0.1/32"},
		Destination:  "0.0.0.0/0",
	}
	b.cache.globalRouteRules["rule-v6"] = &RouteFirewallRule{
		RouteID:      "route-dynamic",
		SourceRanges: []string{"fd00::1/128"},
		Destination:  "::/0",
	}

	view := &PeerRoutesView{
		RouteFirewallRuleIDs: []string{"rule-v4", "rule-v6"},
	}

	// Add a v4 source: should only go to the v4 rule.
	b.updateRouteFirewallRules(view, []*RouteFirewallRuleUpdate{
		{RuleID: "route-dynamic", AddSourceIP: "100.64.0.2"},
	})

	assert.Contains(t, b.cache.globalRouteRules["rule-v4"].SourceRanges, "100.64.0.2/32")
	assert.NotContains(t, b.cache.globalRouteRules["rule-v6"].SourceRanges, "100.64.0.2/32",
		"v4 source should not leak into v6 rule")

	// Add a v6 source: should only go to the v6 rule.
	b.updateRouteFirewallRules(view, []*RouteFirewallRuleUpdate{
		{RuleID: "route-dynamic", AddSourceIP: "fd00::2"},
	})

	assert.Contains(t, b.cache.globalRouteRules["rule-v6"].SourceRanges, "fd00::2/128")
	assert.NotContains(t, b.cache.globalRouteRules["rule-v4"].SourceRanges, "fd00::2/128",
		"v6 source should not leak into v4 rule")
}

func TestUpdateRouteFirewallRules_WildcardSkip(t *testing.T) {
	b := newTestBuilder()

	b.cache.globalRouteRules["rule-wildcard"] = &RouteFirewallRule{
		RouteID:      "route-1",
		SourceRanges: []string{"0.0.0.0/0"},
		Destination:  "10.0.0.0/8",
	}

	view := &PeerRoutesView{
		RouteFirewallRuleIDs: []string{"rule-wildcard"},
	}

	b.updateRouteFirewallRules(view, []*RouteFirewallRuleUpdate{
		{RuleID: "route-1", AddSourceIP: "100.64.0.5"},
	})

	assert.Equal(t, []string{"0.0.0.0/0"}, b.cache.globalRouteRules["rule-wildcard"].SourceRanges,
		"wildcard rule should not get individual sources appended")
}

func TestCalculateRouteFirewallUpdates_DualStack(t *testing.T) {
	b := newTestBuilder()

	// Routing peer "router-1" owns a no-ACG route.
	b.cache.noACGRoutes["route-exit"] = &RouteOwnerInfo{
		PeerID:  "router-1",
		RouteID: "route-exit",
	}
	b.cache.peerRoutes["router-1"] = &PeerRoutesView{}

	newPeer := &nbpeer.Peer{
		ID:   "new-peer",
		IP:   netip.MustParseAddr("100.64.0.5"),
		IPv6: netip.MustParseAddr("fd00::5"),
	}

	updates := make(map[string]*PeerUpdateDelta)
	b.calculateRouteFirewallUpdates("new-peer", newPeer, nil, updates)

	require.Contains(t, updates, "router-1")
	delta := updates["router-1"]

	var v4Found, v6Found bool
	for _, u := range delta.UpdateRouteFirewallRules {
		if u.RuleID == "route-exit" && u.AddSourceIP == "100.64.0.5" {
			v4Found = true
		}
		if u.RuleID == "route-exit" && u.AddSourceIP == "fd00::5" {
			v6Found = true
		}
	}
	assert.True(t, v4Found, "v4 source should be enqueued")
	assert.True(t, v6Found, "v6 source should be enqueued")
}

func TestCalculateRouteFirewallUpdates_V4Only(t *testing.T) {
	b := newTestBuilder()

	b.cache.noACGRoutes["route-1"] = &RouteOwnerInfo{
		PeerID:  "router-1",
		RouteID: "route-1",
	}
	b.cache.peerRoutes["router-1"] = &PeerRoutesView{}

	// Peer without IPv6.
	newPeer := &nbpeer.Peer{
		ID: "new-peer",
		IP: netip.MustParseAddr("100.64.0.5"),
	}

	updates := make(map[string]*PeerUpdateDelta)
	b.calculateRouteFirewallUpdates("new-peer", newPeer, nil, updates)

	require.Contains(t, updates, "router-1")
	delta := updates["router-1"]

	require.Len(t, delta.UpdateRouteFirewallRules, 1)
	assert.Equal(t, "100.64.0.5", delta.UpdateRouteFirewallRules[0].AddSourceIP)
}
