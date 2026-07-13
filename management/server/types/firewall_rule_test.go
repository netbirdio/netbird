package types

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/domain"
)

func TestSplitPeerSourcesByFamily(t *testing.T) {
	peers := []*nbpeer.Peer{
		{
			IP:   netip.MustParseAddr("100.64.0.1"),
			IPv6: netip.MustParseAddr("fd00::1"),
		},
		{
			IP: netip.MustParseAddr("100.64.0.2"),
		},
		{
			IP:   netip.MustParseAddr("100.64.0.3"),
			IPv6: netip.MustParseAddr("fd00::3"),
		},
		nil,
	}

	v4, v6 := splitPeerSourcesByFamily(peers)

	assert.Equal(t, []string{"100.64.0.1/32", "100.64.0.2/32", "100.64.0.3/32"}, v4)
	assert.Equal(t, []string{"fd00::1/128", "fd00::3/128"}, v6)
}

func TestGenerateRouteFirewallRules_V4Route(t *testing.T) {
	peers := []*nbpeer.Peer{
		{
			IP:   netip.MustParseAddr("100.64.0.1"),
			IPv6: netip.MustParseAddr("fd00::1"),
		},
		{
			IP: netip.MustParseAddr("100.64.0.2"),
		},
	}

	r := &route.Route{
		ID:      "route1",
		Network: netip.MustParsePrefix("10.0.0.0/24"),
	}
	rule := &PolicyRule{
		PolicyID: "policy1",
		ID:       "rule1",
		Action:   PolicyTrafficActionAccept,
		Protocol: PolicyRuleProtocolALL,
	}

	rules := generateRouteFirewallRules(context.Background(), r, rule, peers, FirewallRuleDirectionIN, true)

	require.Len(t, rules, 1)
	assert.Equal(t, []string{"100.64.0.1/32", "100.64.0.2/32"}, rules[0].SourceRanges, "v4 route should only have v4 sources")
	assert.Equal(t, "10.0.0.0/24", rules[0].Destination)
}

func TestGenerateRouteFirewallRules_V6Route(t *testing.T) {
	peers := []*nbpeer.Peer{
		{
			IP:   netip.MustParseAddr("100.64.0.1"),
			IPv6: netip.MustParseAddr("fd00::1"),
		},
		{
			IP: netip.MustParseAddr("100.64.0.2"),
		},
	}

	r := &route.Route{
		ID:      "route1",
		Network: netip.MustParsePrefix("2001:db8::/32"),
	}
	rule := &PolicyRule{
		PolicyID: "policy1",
		ID:       "rule1",
		Action:   PolicyTrafficActionAccept,
		Protocol: PolicyRuleProtocolALL,
	}

	rules := generateRouteFirewallRules(context.Background(), r, rule, peers, FirewallRuleDirectionIN, true)

	require.Len(t, rules, 1)
	assert.Equal(t, []string{"fd00::1/128"}, rules[0].SourceRanges, "v6 route should only have v6 sources")
}

func TestGenerateRouteFirewallRules_DynamicRoute_DualStack(t *testing.T) {
	peers := []*nbpeer.Peer{
		{
			IP:   netip.MustParseAddr("100.64.0.1"),
			IPv6: netip.MustParseAddr("fd00::1"),
		},
		{
			IP: netip.MustParseAddr("100.64.0.2"),
		},
	}

	r := &route.Route{
		ID:          "route1",
		NetworkType: route.DomainNetwork,
		Domains:     domain.List{"example.com"},
	}
	rule := &PolicyRule{
		PolicyID: "policy1",
		ID:       "rule1",
		Action:   PolicyTrafficActionAccept,
		Protocol: PolicyRuleProtocolALL,
	}

	rules := generateRouteFirewallRules(context.Background(), r, rule, peers, FirewallRuleDirectionIN, true)

	require.Len(t, rules, 2, "dynamic route should produce both v4 and v6 rules")
	assert.Equal(t, []string{"100.64.0.1/32", "100.64.0.2/32"}, rules[0].SourceRanges)
	assert.Equal(t, []string{"fd00::1/128"}, rules[1].SourceRanges)
	assert.Equal(t, rules[0].Domains, rules[1].Domains)
	assert.True(t, rules[0].IsDynamic)
	assert.True(t, rules[1].IsDynamic)
}

func TestGenerateRouteFirewallRules_DynamicRoute_NoV6Peers(t *testing.T) {
	peers := []*nbpeer.Peer{
		{IP: netip.MustParseAddr("100.64.0.1")},
		{IP: netip.MustParseAddr("100.64.0.2")},
	}

	r := &route.Route{
		ID:          "route1",
		NetworkType: route.DomainNetwork,
		Domains:     domain.List{"example.com"},
	}
	rule := &PolicyRule{
		PolicyID: "policy1",
		ID:       "rule1",
		Action:   PolicyTrafficActionAccept,
		Protocol: PolicyRuleProtocolALL,
	}

	rules := generateRouteFirewallRules(context.Background(), r, rule, peers, FirewallRuleDirectionIN, true)

	require.Len(t, rules, 1, "no v6 peers means only v4 rule")
	assert.Equal(t, []string{"100.64.0.1/32", "100.64.0.2/32"}, rules[0].SourceRanges)
}

func TestGenerateRouteFirewallRules_IncludeIPv6False(t *testing.T) {
	peers := []*nbpeer.Peer{
		{
			IP:   netip.MustParseAddr("100.64.0.1"),
			IPv6: netip.MustParseAddr("fd00::1"),
		},
		{
			IP:   netip.MustParseAddr("100.64.0.2"),
			IPv6: netip.MustParseAddr("fd00::2"),
		},
	}

	t.Run("v6 route excluded", func(t *testing.T) {
		r := &route.Route{
			ID:      "route1",
			Network: netip.MustParsePrefix("2001:db8::/32"),
		}
		rule := &PolicyRule{
			PolicyID: "policy1",
			ID:       "rule1",
			Action:   PolicyTrafficActionAccept,
			Protocol: PolicyRuleProtocolALL,
		}

		rules := generateRouteFirewallRules(context.Background(), r, rule, peers, FirewallRuleDirectionIN, false)
		assert.Empty(t, rules, "v6 route should produce no rules when includeIPv6 is false")
	})

	t.Run("dynamic route only v4", func(t *testing.T) {
		r := &route.Route{
			ID:          "route1",
			NetworkType: route.DomainNetwork,
			Domains:     domain.List{"example.com"},
		}
		rule := &PolicyRule{
			PolicyID: "policy1",
			ID:       "rule1",
			Action:   PolicyTrafficActionAccept,
			Protocol: PolicyRuleProtocolALL,
		}

		rules := generateRouteFirewallRules(context.Background(), r, rule, peers, FirewallRuleDirectionIN, false)
		require.Len(t, rules, 1, "dynamic route with includeIPv6=false should produce only v4 rule")
		assert.Equal(t, []string{"100.64.0.1/32", "100.64.0.2/32"}, rules[0].SourceRanges)
	})
}
