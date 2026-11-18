package networkmap_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	nbtypes "github.com/netbirdio/netbird/shared/management/types"
)

const (
	resourceID = "res-1"
	networkID  = "net-1"
	routerID   = "peer-router"
)

// resourceSourceNMD builds an account with one subnet resource behind a routing
// peer and a client peer. The policy makes the resource the source and the
// client group the destination, optionally bidirectional.
func resourceSourceNMD(t *testing.T, bidirectional bool) (*networkmap.NetworkMapData, *nmdata.Peer, *nmdata.Peer) {
	t.Helper()

	client := newPeer(targetID, 1)
	router := newPeer(routerID, 2)
	nmd := newNMD(client, router)
	addGroup(nmd, "g-clients", client.ID)
	resGroup := addGroup(nmd, "g-resources")
	resGroup.Resources = []nmdata.Resource{{ID: resourceID, Type: string(nbtypes.ResourceTypeSubnet)}}

	nmd.NetworkResources = []*nmdata.NetworkResource{{
		ID:        resourceID,
		NetworkID: networkID,
		Name:      "site-b",
		Type:      string(nbtypes.ResourceTypeSubnet),
		Prefix:    netip.MustParsePrefix("10.20.0.0/24"),
		Enabled:   true,
	}}
	nmd.Routers = map[string]map[string]*nmdata.NetworkRouter{
		networkID: {router.ID: {Enabled: true, Masquerade: true, Metric: 9999}},
	}

	rule := newRule([]string{"g-resources"}, []string{"g-clients"})
	rule.Bidirectional = bidirectional
	pol := newPolicy("p-src", rule)
	nmd.Policies = []*nmdata.Policy{pol}
	nmd.ResourcePolicies = map[string][]*nmdata.Policy{resourceID: {pol}}

	return nmd, client, router
}

func TestResourceAsSource_ClientAcceptsResourcePrefix(t *testing.T) {
	nmd, client, _ := resourceSourceNMD(t, false)

	c := compute(nmd, client.ID)
	require.Contains(t, c.ResourceSourcePolicies[resourceID], "p-src", "resource must be flagged as source of the policy")

	nm := c.Calculate(context.Background())

	var prefixRules []*nbtypes.FirewallRule
	for _, r := range nm.FirewallRules {
		if r.SourcePrefix.IsValid() {
			prefixRules = append(prefixRules, r)
		}
	}
	require.Len(t, prefixRules, 1, "client needs one inbound rule sourced from the resource CIDR")
	assert.Equal(t, netip.MustParsePrefix("10.20.0.0/24"), prefixRules[0].SourcePrefix)
	assert.Equal(t, "tcp", prefixRules[0].Protocol)
	assert.Equal(t, nbtypes.FirewallRuleDirectionIN, prefixRules[0].Direction)
	assert.Empty(t, prefixRules[0].PeerIP, "a prefix source carries no peer IP")
}

func TestResourceAsSource_RouterBuildsReverseForwardRule(t *testing.T) {
	nmd, client, router := resourceSourceNMD(t, false)

	nm := compute(nmd, router.ID).Calculate(context.Background())

	require.Len(t, nm.RoutesFirewallRules, 1, "source-only resource gets only the resource -> client rule")
	rule := nm.RoutesFirewallRules[0]
	assert.True(t, rule.ResourceIsSource)
	assert.Equal(t, "10.20.0.0/24", rule.Destination, "route destination stays the resource network")
	assert.Equal(t, []string{client.IP.String() + "/32"}, rule.SourceRanges, "source ranges carry the destination peers")

	require.Len(t, nm.Routes, 1)
	assert.True(t, nm.Routes[0].DisableOutboundMasquerade, "inverse masquerade is off when the resource initiates traffic")
	assert.True(t, nm.Routes[0].Masquerade, "forward masquerade is unchanged")
}

func TestResourceAsSource_BidirectionalEmitsBothDirections(t *testing.T) {
	nmd, client, router := resourceSourceNMD(t, true)

	nm := compute(nmd, router.ID).Calculate(context.Background())

	var forward, reverse int
	for _, r := range nm.RoutesFirewallRules {
		assert.Equal(t, []string{client.IP.String() + "/32"}, r.SourceRanges)
		if r.ResourceIsSource {
			reverse++
		} else {
			forward++
		}
	}
	assert.Equal(t, 1, forward, "bidirectional keeps the client -> resource rule")
	assert.Equal(t, 1, reverse, "bidirectional adds the resource -> client rule")
}

func TestResourceAsDestination_KeepsInverseMasquerade(t *testing.T) {
	client := newPeer(targetID, 1)
	router := newPeer(routerID, 2)
	nmd := newNMD(client, router)
	addGroup(nmd, "g-clients", client.ID)
	resGroup := addGroup(nmd, "g-resources")
	resGroup.Resources = []nmdata.Resource{{ID: resourceID, Type: string(nbtypes.ResourceTypeSubnet)}}
	nmd.NetworkResources = []*nmdata.NetworkResource{{
		ID:        resourceID,
		NetworkID: networkID,
		Name:      "site-b",
		Type:      string(nbtypes.ResourceTypeSubnet),
		Prefix:    netip.MustParsePrefix("10.20.0.0/24"),
		Enabled:   true,
	}}
	nmd.Routers = map[string]map[string]*nmdata.NetworkRouter{
		networkID: {router.ID: {Enabled: true, Masquerade: true, Metric: 9999}},
	}
	rule := newRule([]string{"g-clients"}, []string{"g-resources"})
	rule.Bidirectional = false
	pol := newPolicy("p-dst", rule)
	nmd.Policies = []*nmdata.Policy{pol}
	nmd.ResourcePolicies = map[string][]*nmdata.Policy{resourceID: {pol}}

	c := compute(nmd, router.ID)
	assert.Empty(t, c.ResourceSourcePolicies, "no policy has the resource as its source")

	nm := c.Calculate(context.Background())
	require.Len(t, nm.Routes, 1)
	assert.False(t, nm.Routes[0].DisableOutboundMasquerade)
	require.Len(t, nm.RoutesFirewallRules, 1)
	assert.False(t, nm.RoutesFirewallRules[0].ResourceIsSource)
	assert.Empty(t, compute(nmd, client.ID).Calculate(context.Background()).FirewallRules,
		"a destination-only resource adds no inbound prefix rule on clients")
}

func TestEncode_ResourceSourceFields(t *testing.T) {
	prefixRule := &nbtypes.FirewallRule{
		PolicyID:     "p-src",
		Direction:    nbtypes.FirewallRuleDirectionIN,
		Action:       string(nbtypes.PolicyTrafficActionAccept),
		Protocol:     string(nbtypes.PolicyRuleProtocolTCP),
		Port:         "443",
		SourcePrefix: netip.MustParsePrefix("10.20.0.7/24"),
	}

	t.Run("prefix source is sent as a masked source prefix", func(t *testing.T) {
		out := networkmap.ToProtocolFirewallRules([]*nbtypes.FirewallRule{prefixRule}, true, true)
		require.Len(t, out, 1)
		require.Len(t, out[0].SourcePrefixes, 1)
		assert.Empty(t, out[0].PeerIP, "a prefix source has no peer IP")
		assert.Equal(t, "443", out[0].Port)
	})

	t.Run("dropped for clients without source prefix support", func(t *testing.T) {
		out := networkmap.ToProtocolFirewallRules([]*nbtypes.FirewallRule{prefixRule}, true, false)
		assert.Empty(t, out, "an old client cannot read the prefix, so the rule must not be sent as a wildcard")
	})

	t.Run("v6 source dropped for peers without v6", func(t *testing.T) {
		v6 := *prefixRule
		v6.SourcePrefix = netip.MustParsePrefix("fd00:20::/64")
		assert.Empty(t, networkmap.ToProtocolFirewallRules([]*nbtypes.FirewallRule{&v6}, false, true))
		assert.Len(t, networkmap.ToProtocolFirewallRules([]*nbtypes.FirewallRule{&v6}, true, true), 1)
	})

	t.Run("route and route rule flags", func(t *testing.T) {
		route := networkmap.ToProtocolRoute(&nmdata.Route{ID: "r", Network: netip.MustParsePrefix("10.20.0.0/24"), DisableOutboundMasquerade: true})
		assert.True(t, route.DisableOutboundMasquerade)

		rules := networkmap.ToProtocolRoutesFirewallRules([]*nbtypes.RouteFirewallRule{{ResourceIsSource: true}})
		require.Len(t, rules, 1)
		assert.True(t, rules[0].ResourceIsSource)
	})
}
