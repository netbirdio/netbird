package types_test

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

func networkMapFromComponents(t *testing.T, account *types.Account, peerID string, validatedPeers map[string]struct{}) *types.NetworkMap {
	t.Helper()
	return account.GetPeerNetworkMapFromComponents(
		context.Background(),
		peerID,
		account.GetPeersCustomZone(context.Background(), "netbird.io"),
		nil,
		validatedPeers,
		account.GetResourcePoliciesMap(),
		account.GetResourceRoutersMap(),
		nil,
		account.GetActiveGroupUsers(),
	)
}

func allPeersValidated(account *types.Account, excludePeerIDs ...string) map[string]struct{} {
	excludeSet := make(map[string]struct{}, len(excludePeerIDs))
	for _, id := range excludePeerIDs {
		excludeSet[id] = struct{}{}
	}
	validated := make(map[string]struct{}, len(account.Peers))
	for id := range account.Peers {
		if _, excluded := excludeSet[id]; !excluded {
			validated[id] = struct{}{}
		}
	}
	return validated
}

func peerIDs(peers []*nbpeer.Peer) []string {
	ids := make([]string, len(peers))
	for i, p := range peers {
		ids[i] = p.ID
	}
	return ids
}

func TestNetworkMapComponents_RegularPeerConnectivity(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	nm := networkMapFromComponents(t, account, "peer-src-1", validated)

	assert.NotNil(t, nm)
	assert.Contains(t, peerIDs(nm.Peers), "peer-dst-1", "should see peer from destination group via bidirectional policy")
	assert.Contains(t, peerIDs(nm.Peers), "peer-router-1", "should see router peer via resource policy")
	assert.NotContains(t, peerIDs(nm.Peers), "peer-src-1", "should not see itself")
	assert.Empty(t, nm.OfflinePeers, "no expired peers expected")
}

func TestNetworkMapComponents_IntraGroupConnectivity(t *testing.T) {
	account := createComponentTestAccount()
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-intra-src", Name: "Intra-source connectivity", Enabled: true, AccountID: account.Id,
		Rules: []*types.PolicyRule{{
			ID: "rule-intra-src", Name: "src <-> src", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
			Bidirectional: true,
			Sources:       []string{"group-src"}, Destinations: []string{"group-src"},
		}},
	})
	validated := allPeersValidated(account)

	nm := networkMapFromComponents(t, account, "peer-src-1", validated)
	assert.Contains(t, peerIDs(nm.Peers), "peer-src-2", "should see peer from same group with intra-group policy")
}

func TestNetworkMapComponents_FirewallRules(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	nm := networkMapFromComponents(t, account, "peer-src-1", validated)

	require.NotEmpty(t, nm.FirewallRules, "firewall rules should be generated")

	var hasAcceptAll bool
	for _, rule := range nm.FirewallRules {
		if rule.Protocol == string(types.PolicyRuleProtocolALL) && rule.Action == string(types.PolicyTrafficActionAccept) {
			hasAcceptAll = true
		}
	}
	assert.True(t, hasAcceptAll, "should have an accept-all firewall rule from the base policy")
}

func TestNetworkMapComponents_LoginExpiration(t *testing.T) {
	account := createComponentTestAccount()
	account.Settings.PeerLoginExpirationEnabled = true
	account.Settings.PeerLoginExpiration = 1 * time.Hour

	expiredTime := time.Now().Add(-2 * time.Hour)
	account.Peers["peer-dst-1"].LoginExpirationEnabled = true
	account.Peers["peer-dst-1"].LastLogin = &expiredTime

	validated := allPeersValidated(account)
	nm := networkMapFromComponents(t, account, "peer-src-1", validated)

	assert.Contains(t, peerIDs(nm.OfflinePeers), "peer-dst-1", "expired peer should be in OfflinePeers")
	assert.NotContains(t, peerIDs(nm.Peers), "peer-dst-1", "expired peer should NOT be in active Peers")
}

func TestNetworkMapComponents_InvalidatedPeerExcluded(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account, "peer-dst-1")

	nm := networkMapFromComponents(t, account, "peer-src-1", validated)

	assert.NotContains(t, peerIDs(nm.Peers), "peer-dst-1", "non-validated peer should be excluded")
	assert.NotContains(t, peerIDs(nm.OfflinePeers), "peer-dst-1", "non-validated peer should not be in offline peers either")
}

func TestNetworkMapComponents_NonValidatedTargetPeer(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account, "peer-src-1")

	nm := networkMapFromComponents(t, account, "peer-src-1", validated)

	assert.Empty(t, nm.Peers, "non-validated target peer should get empty network map")
	assert.Empty(t, nm.FirewallRules)
}

func TestNetworkMapComponents_NetworkResourceRoutes_SourcePeer(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	nm := networkMapFromComponents(t, account, "peer-src-1", validated)

	var hasResourceRoute bool
	for _, r := range nm.Routes {
		if r.Network.String() == "10.200.0.1/32" {
			hasResourceRoute = true
			break
		}
	}
	assert.True(t, hasResourceRoute, "source peer should receive route to network resource via router")
	assert.Contains(t, peerIDs(nm.Peers), "peer-router-1", "source peer should see the routing peer")
}

func TestNetworkMapComponents_NetworkResourceRoutes_RouterPeer(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	nm := networkMapFromComponents(t, account, "peer-router-1", validated)

	var hasResourceRoute bool
	for _, r := range nm.Routes {
		if r.Network.String() == "10.200.0.1/32" {
			hasResourceRoute = true
			break
		}
	}
	assert.True(t, hasResourceRoute, "router peer should receive network resource route")
	assert.NotEmpty(t, nm.RoutesFirewallRules, "router peer should have route firewall rules for the resource")
}

func TestNetworkMapComponents_NetworkResourceRoutes_UnrelatedPeer(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	nm := networkMapFromComponents(t, account, "peer-dst-1", validated)

	for _, r := range nm.Routes {
		assert.NotEqual(t, "10.200.0.1/32", r.Network.String(), "unrelated peer should not receive network resource route")
	}
}

func TestNetworkMapComponents_NetworkResource_WithPostureCheck(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	account.PostureChecks = []*posture.Checks{
		{ID: "pc-version", Name: "Version check", Checks: posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{MinVersion: "0.30.0"},
		}},
	}
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-posture-resource", Name: "Posture resource access", Enabled: true, AccountID: account.Id,
		SourcePostureChecks: []string{"pc-version"},
		Rules: []*types.PolicyRule{{
			ID: "rule-posture-resource", Name: "Posture -> Resource", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
			Sources:             []string{"group-src"},
			DestinationResource: types.Resource{ID: "resource-guarded"},
		}},
	})

	account.NetworkResources = append(account.NetworkResources, &resourceTypes.NetworkResource{
		ID: "resource-guarded", NetworkID: "net-guarded", AccountID: account.Id, Enabled: true,
		Type: resourceTypes.Host, Prefix: netip.MustParsePrefix("10.200.1.1/32"), Address: "10.200.1.1/32",
	})
	account.Networks = append(account.Networks, &networkTypes.Network{
		ID: "net-guarded", Name: "Guarded Net", AccountID: account.Id,
	})
	account.NetworkRouters = append(account.NetworkRouters, &routerTypes.NetworkRouter{
		ID: "router-guarded", NetworkID: "net-guarded", Peer: "peer-router-1", Enabled: true, AccountID: account.Id,
	})

	t.Run("peer passes posture check", func(t *testing.T) {
		account.Peers["peer-src-1"].Meta.WtVersion = "0.35.0"
		nm := networkMapFromComponents(t, account, "peer-src-1", validated)

		var hasGuardedRoute bool
		for _, r := range nm.Routes {
			if r.Network.String() == "10.200.1.1/32" {
				hasGuardedRoute = true
			}
		}
		assert.True(t, hasGuardedRoute, "peer passing posture check should get guarded resource route")
	})

	t.Run("peer fails posture check", func(t *testing.T) {
		account.Peers["peer-src-1"].Meta.WtVersion = "0.20.0"
		nm := networkMapFromComponents(t, account, "peer-src-1", validated)

		for _, r := range nm.Routes {
			assert.NotEqual(t, "10.200.1.1/32", r.Network.String(), "peer failing posture check should NOT get guarded resource route")
		}
	})
}

func TestNetworkMapComponents_NetworkResource_MultiplePostureChecks(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	account.PostureChecks = []*posture.Checks{
		{ID: "pc-version", Name: "Version", Checks: posture.ChecksDefinition{
			NBVersionCheck: &posture.NBVersionCheck{MinVersion: "0.30.0"},
		}},
		{ID: "pc-os", Name: "OS check", Checks: posture.ChecksDefinition{
			OSVersionCheck: &posture.OSVersionCheck{Linux: &posture.MinKernelVersionCheck{MinKernelVersion: "5.0"}},
		}},
	}

	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-multi-posture", Name: "Multi posture", Enabled: true, AccountID: account.Id,
		SourcePostureChecks: []string{"pc-version", "pc-os"},
		Rules: []*types.PolicyRule{{
			ID: "rule-multi-posture", Name: "Multi posture rule", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
			Sources:             []string{"group-src"},
			DestinationResource: types.Resource{ID: "resource-strict"},
		}},
	})

	account.NetworkResources = append(account.NetworkResources, &resourceTypes.NetworkResource{
		ID: "resource-strict", NetworkID: "net-strict", AccountID: account.Id, Enabled: true,
		Type: resourceTypes.Host, Prefix: netip.MustParsePrefix("10.200.2.1/32"), Address: "10.200.2.1/32",
	})
	account.Networks = append(account.Networks, &networkTypes.Network{
		ID: "net-strict", Name: "Strict Net", AccountID: account.Id,
	})
	account.NetworkRouters = append(account.NetworkRouters, &routerTypes.NetworkRouter{
		ID: "router-strict", NetworkID: "net-strict", Peer: "peer-router-1", Enabled: true, AccountID: account.Id,
	})

	t.Run("passes both posture checks", func(t *testing.T) {
		account.Peers["peer-src-1"].Meta.WtVersion = "0.35.0"
		account.Peers["peer-src-1"].Meta.GoOS = "linux"
		account.Peers["peer-src-1"].Meta.KernelVersion = "6.1.0"
		nm := networkMapFromComponents(t, account, "peer-src-1", validated)

		var found bool
		for _, r := range nm.Routes {
			if r.Network.String() == "10.200.2.1/32" {
				found = true
			}
		}
		assert.True(t, found, "peer passing both checks should get resource route")
	})

	t.Run("fails version posture check", func(t *testing.T) {
		account.Peers["peer-src-1"].Meta.WtVersion = "0.20.0"
		account.Peers["peer-src-1"].Meta.KernelVersion = "6.1.0"
		nm := networkMapFromComponents(t, account, "peer-src-1", validated)

		for _, r := range nm.Routes {
			assert.NotEqual(t, "10.200.2.1/32", r.Network.String(), "peer failing version check should NOT get resource route")
		}
	})

	t.Run("fails OS posture check", func(t *testing.T) {
		account.Peers["peer-src-1"].Meta.WtVersion = "0.35.0"
		account.Peers["peer-src-1"].Meta.KernelVersion = "4.0.0"
		nm := networkMapFromComponents(t, account, "peer-src-1", validated)

		for _, r := range nm.Routes {
			assert.NotEqual(t, "10.200.2.1/32", r.Network.String(), "peer failing OS check should NOT get resource route")
		}
	})
}

func TestNetworkMapComponents_RouterPeerFirewallRules(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	nm := networkMapFromComponents(t, account, "peer-router-1", validated)

	var resourceFWRules []*types.RouteFirewallRule
	for _, rule := range nm.RoutesFirewallRules {
		if rule.Destination == "10.200.0.1/32" {
			resourceFWRules = append(resourceFWRules, rule)
		}
	}
	assert.NotEmpty(t, resourceFWRules, "router should have firewall rules for the network resource")

	var hasSourcePeerIP bool
	for _, rule := range resourceFWRules {
		for _, sr := range rule.SourceRanges {
			if sr == account.Peers["peer-src-1"].IP.String()+"/32" || sr == account.Peers["peer-src-2"].IP.String()+"/32" {
				hasSourcePeerIP = true
			}
		}
	}
	assert.True(t, hasSourcePeerIP, "resource firewall rules should include source peer IPs")
}

func TestNetworkMapComponents_DNSManagement(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	t.Run("peer in DNS-enabled group", func(t *testing.T) {
		nm := networkMapFromComponents(t, account, "peer-src-1", validated)
		assert.True(t, nm.DNSConfig.ServiceEnable, "peer in non-disabled group should have DNS enabled")
	})

	t.Run("peer in DNS-disabled group", func(t *testing.T) {
		nm := networkMapFromComponents(t, account, "peer-dst-1", validated)
		assert.False(t, nm.DNSConfig.ServiceEnable, "peer in DNS-disabled group should have DNS disabled")
	})
}

func TestNetworkMapComponents_NameServerGroups(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	nm := networkMapFromComponents(t, account, "peer-src-1", validated)
	assert.True(t, nm.DNSConfig.ServiceEnable)

	var hasNSGroup bool
	for _, ns := range nm.DNSConfig.NameServerGroups {
		if ns.ID == "ns-main" {
			hasNSGroup = true
		}
	}
	assert.True(t, hasNSGroup, "peer in NS group should receive nameserver configuration")
}

func TestNetworkMapComponents_RoutesWithHADeduplication(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	account.Routes["route-ha-1"] = &route.Route{
		ID: "route-ha-1", Network: netip.MustParsePrefix("172.16.0.0/16"),
		Peer: account.Peers["peer-dst-1"].Key, PeerID: "peer-dst-1",
		Enabled: true, Metric: 100, AccountID: account.Id,
		Groups: []string{"group-src", "group-dst"}, PeerGroups: []string{"group-dst"},
	}
	account.Routes["route-ha-2"] = &route.Route{
		ID: "route-ha-2", Network: netip.MustParsePrefix("172.16.0.0/16"),
		Peer: account.Peers["peer-src-1"].Key, PeerID: "peer-src-1",
		Enabled: true, Metric: 200, AccountID: account.Id,
		Groups: []string{"group-src", "group-dst"}, PeerGroups: []string{"group-src"},
	}

	nm := networkMapFromComponents(t, account, "peer-src-1", validated)

	haCount := 0
	for _, r := range nm.Routes {
		if r.Network.String() == "172.16.0.0/16" {
			haCount++
		}
	}
	assert.Equal(t, 1, haCount, "peer should only receive one route from HA group (not both, since it's a member of one)")
}

func TestNetworkMapComponents_RoutesFirewallRulesForAccessControl(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	account.Routes["route-acl"] = &route.Route{
		ID: "route-acl", Network: netip.MustParsePrefix("192.168.100.0/24"),
		Peer: account.Peers["peer-src-1"].Key, PeerID: "peer-src-1",
		Enabled: true, Metric: 100, AccountID: account.Id,
		Groups:              []string{"group-dst"},
		PeerGroups:          []string{"group-src"},
		AccessControlGroups: []string{"group-dst"},
	}

	nm := networkMapFromComponents(t, account, "peer-src-1", validated)

	var hasFWRule bool
	for _, rule := range nm.RoutesFirewallRules {
		if rule.Destination == "192.168.100.0/24" {
			hasFWRule = true
		}
	}
	assert.True(t, hasFWRule, "routing peer should have firewall rules for route with access control groups")
}

func TestNetworkMapComponents_RoutesDefaultPermit(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	account.Routes["route-open"] = &route.Route{
		ID: "route-open", Network: netip.MustParsePrefix("10.99.0.0/16"),
		Peer: account.Peers["peer-src-1"].Key, PeerID: "peer-src-1",
		Enabled: true, Metric: 100, AccountID: account.Id,
		Groups:     []string{"group-src"},
		PeerGroups: []string{"group-src"},
	}

	nm := networkMapFromComponents(t, account, "peer-src-1", validated)

	var hasFWRule bool
	for _, rule := range nm.RoutesFirewallRules {
		if rule.Destination == "10.99.0.0/16" {
			hasFWRule = true
		}
	}
	assert.True(t, hasFWRule, "route without access control groups should have default permit firewall rules")
}

func TestNetworkMapComponents_SSHAuthorizedUsers(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	account.Peers["peer-dst-1"].SSHEnabled = true

	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-ssh", Name: "SSH Access", Enabled: true, AccountID: account.Id,
		Rules: []*types.PolicyRule{{
			ID: "rule-ssh", Name: "SSH to dst", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
			Bidirectional: true,
			Sources:       []string{"group-src"}, Destinations: []string{"group-dst"},
		}},
	})

	nm := networkMapFromComponents(t, account, "peer-dst-1", validated)
	assert.True(t, nm.EnableSSH, "SSH-enabled peer with matching policy should have EnableSSH")
}

func TestNetworkMapComponents_DisabledPolicyIgnored(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	for _, p := range account.Policies {
		p.Enabled = false
	}

	nm := networkMapFromComponents(t, account, "peer-src-1", validated)
	assert.Empty(t, nm.Peers, "with all policies disabled, peer should see no other peers")
	assert.Empty(t, nm.FirewallRules)
}

func TestNetworkMapComponents_DisabledRouteIgnored(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	for _, r := range account.Routes {
		r.Enabled = false
	}
	for _, r := range account.NetworkResources {
		r.Enabled = false
	}

	nm := networkMapFromComponents(t, account, "peer-src-1", validated)
	assert.Empty(t, nm.Routes, "disabled routes should not appear in network map")
}

func TestNetworkMapComponents_DisabledNetworkResourceIgnored(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	for _, r := range account.NetworkResources {
		r.Enabled = false
	}

	nm := networkMapFromComponents(t, account, "peer-router-1", validated)

	for _, r := range nm.Routes {
		assert.NotEqual(t, "10.200.0.1/32", r.Network.String(), "disabled resource should not generate routes")
	}
}

func TestNetworkMapComponents_BidirectionalPolicy(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	nmSrc := networkMapFromComponents(t, account, "peer-src-1", validated)
	nmDst := networkMapFromComponents(t, account, "peer-dst-1", validated)

	assert.Contains(t, peerIDs(nmSrc.Peers), "peer-dst-1", "src should see dst via bidirectional policy")
	assert.Contains(t, peerIDs(nmDst.Peers), "peer-src-1", "dst should see src via bidirectional policy")
}

func TestNetworkMapComponents_DropPolicy(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-drop", Name: "Drop traffic", Enabled: true, AccountID: account.Id,
		Rules: []*types.PolicyRule{{
			ID: "rule-drop", Name: "Drop src->dst", Enabled: true,
			Action: types.PolicyTrafficActionDrop, Protocol: types.PolicyRuleProtocolTCP,
			Ports:   []string{"5432"},
			Sources: []string{"group-src"}, Destinations: []string{"group-dst"},
		}},
	})

	nm := networkMapFromComponents(t, account, "peer-src-1", validated)

	var hasDropRule bool
	for _, rule := range nm.FirewallRules {
		if rule.Action == string(types.PolicyTrafficActionDrop) && rule.Port == "5432" {
			hasDropRule = true
		}
	}
	assert.True(t, hasDropRule, "drop policy should generate drop firewall rule")
}

func TestNetworkMapComponents_PortRangePolicy(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	account.Peers["peer-src-1"].Meta.WtVersion = "0.50.0"

	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-range", Name: "Port range", Enabled: true, AccountID: account.Id,
		Rules: []*types.PolicyRule{{
			ID: "rule-range", Name: "Range rule", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolTCP,
			PortRanges: []types.RulePortRange{{Start: 8080, End: 8090}},
			Sources:    []string{"group-src"}, Destinations: []string{"group-dst"},
		}},
	})

	nm := networkMapFromComponents(t, account, "peer-src-1", validated)

	var hasRangeRule bool
	for _, rule := range nm.FirewallRules {
		if rule.PortRange.Start == 8080 && rule.PortRange.End == 8090 {
			hasRangeRule = true
		}
	}
	assert.True(t, hasRangeRule, "port range policy should generate corresponding firewall rule")
}

func TestNetworkMapComponents_MultipleNetworkResources(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	account.NetworkResources = append(account.NetworkResources, &resourceTypes.NetworkResource{
		ID: "resource-2", NetworkID: "net-1", AccountID: account.Id, Enabled: true,
		Type: resourceTypes.Host, Prefix: netip.MustParsePrefix("10.200.0.2/32"), Address: "10.200.0.2/32",
	})
	account.Groups["group-res2"] = &types.Group{ID: "group-res2", Name: "Resource 2 Group", Peers: []string{"peer-src-1", "peer-src-2"},
		Resources: []types.Resource{{ID: "resource-2"}},
	}
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-res2", Name: "Resource 2 Policy", Enabled: true, AccountID: account.Id,
		Rules: []*types.PolicyRule{{
			ID: "rule-res2", Name: "Access Resource 2", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
			Sources:             []string{"group-src"},
			DestinationResource: types.Resource{ID: "resource-2"},
		}},
	})

	nm := networkMapFromComponents(t, account, "peer-router-1", validated)

	resourceRouteCount := 0
	for _, r := range nm.Routes {
		if r.Network.String() == "10.200.0.1/32" || r.Network.String() == "10.200.0.2/32" {
			resourceRouteCount++
		}
	}
	assert.Equal(t, 2, resourceRouteCount, "router should have routes for both network resources")
}

func TestNetworkMapComponents_DomainNetworkResource(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	account.NetworkResources = append(account.NetworkResources, &resourceTypes.NetworkResource{
		ID: "resource-domain", NetworkID: "net-1", AccountID: account.Id, Enabled: true,
		Type: resourceTypes.Domain, Domain: "api.example.com", Address: "api.example.com",
	})
	account.Groups["group-res-domain"] = &types.Group{
		ID: "group-res-domain", Name: "Domain Resource Group",
		Resources: []types.Resource{{ID: "resource-domain"}},
	}
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-domain", Name: "Domain resource policy", Enabled: true, AccountID: account.Id,
		Rules: []*types.PolicyRule{{
			ID: "rule-domain", Name: "Access domain resource", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
			Sources:             []string{"group-src"},
			DestinationResource: types.Resource{ID: "resource-domain"},
		}},
	})

	nm := networkMapFromComponents(t, account, "peer-src-1", validated)

	var hasDomainRoute bool
	for _, r := range nm.Routes {
		if r.NetworkType == route.DomainNetwork && len(r.Domains) > 0 && r.Domains[0].SafeString() == "api.example.com" {
			hasDomainRoute = true
		}
	}
	assert.True(t, hasDomainRoute, "source peer should receive domain route for domain network resource")
}

func TestNetworkMapComponents_NetworkEmpty(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	nm := networkMapFromComponents(t, account, "nonexistent-peer", validated)

	assert.NotNil(t, nm)
	assert.Empty(t, nm.Peers)
	assert.Empty(t, nm.FirewallRules)
	assert.NotNil(t, nm.Network)
}

func TestNetworkMapComponents_RouterExcludesOtherNetworkRoutes(t *testing.T) {
	account := createComponentTestAccount()
	validated := allPeersValidated(account)

	account.NetworkResources = append(account.NetworkResources, &resourceTypes.NetworkResource{
		ID: "resource-other", NetworkID: "net-other", AccountID: account.Id, Enabled: true,
		Type: resourceTypes.Host, Prefix: netip.MustParsePrefix("10.200.99.1/32"), Address: "10.200.99.1/32",
	})
	account.Networks = append(account.Networks, &networkTypes.Network{
		ID: "net-other", Name: "Other Net", AccountID: account.Id,
	})
	account.NetworkRouters = append(account.NetworkRouters, &routerTypes.NetworkRouter{
		ID: "router-other", NetworkID: "net-other", Peer: "peer-dst-1", Enabled: true, AccountID: account.Id,
	})
	account.Groups["group-res-other"] = &types.Group{ID: "group-res-other", Name: "Other resource group",
		Resources: []types.Resource{{ID: "resource-other"}},
	}
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-other-resource", Name: "Other resource policy", Enabled: true, AccountID: account.Id,
		Rules: []*types.PolicyRule{{
			ID: "rule-other", Name: "Other resource access", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
			Sources:             []string{"group-src"},
			DestinationResource: types.Resource{ID: "resource-other"},
		}},
	})

	nm := networkMapFromComponents(t, account, "peer-router-1", validated)

	for _, r := range nm.Routes {
		assert.NotEqual(t, "10.200.99.1/32", r.Network.String(), "router-1 should NOT get routes for other network's resources")
	}
}

func createComponentTestAccount() *types.Account {
	peers := map[string]*nbpeer.Peer{
		"peer-src-1": {
			ID: "peer-src-1", IP: net.IP{100, 64, 0, 1}, Key: "key-src-1", DNSLabel: "src1",
			Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()}, UserID: "user-1",
			Meta: nbpeer.PeerSystemMeta{WtVersion: "0.35.0", GoOS: "linux"},
		},
		"peer-src-2": {
			ID: "peer-src-2", IP: net.IP{100, 64, 0, 2}, Key: "key-src-2", DNSLabel: "src2",
			Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()}, UserID: "user-1",
			Meta: nbpeer.PeerSystemMeta{WtVersion: "0.35.0", GoOS: "linux"},
		},
		"peer-dst-1": {
			ID: "peer-dst-1", IP: net.IP{100, 64, 0, 3}, Key: "key-dst-1", DNSLabel: "dst1",
			Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()}, UserID: "user-2",
			Meta: nbpeer.PeerSystemMeta{WtVersion: "0.35.0", GoOS: "linux"},
		},
		"peer-router-1": {
			ID: "peer-router-1", IP: net.IP{100, 64, 0, 10}, Key: "key-router-1", DNSLabel: "router1",
			Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()}, UserID: "user-1",
			Meta: nbpeer.PeerSystemMeta{WtVersion: "0.35.0", GoOS: "linux"},
		},
	}

	groups := map[string]*types.Group{
		"group-src": {ID: "group-src", Name: "Sources", Peers: []string{"peer-src-1", "peer-src-2"}},
		"group-dst": {ID: "group-dst", Name: "Destinations", Peers: []string{"peer-dst-1"}},
		"group-all": {ID: "group-all", Name: "All", Peers: []string{"peer-src-1", "peer-src-2", "peer-dst-1", "peer-router-1"}},
		"group-res": {
			ID: "group-res", Name: "Resource Group",
			Resources: []types.Resource{{ID: "resource-1"}},
		},
	}

	policies := []*types.Policy{
		{
			ID: "policy-base", Name: "Base connectivity", Enabled: true,
			Rules: []*types.PolicyRule{{
				ID: "rule-base", Name: "Allow src <-> dst", Enabled: true,
				Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
				Bidirectional: true,
				Sources:       []string{"group-src"}, Destinations: []string{"group-dst"},
			}},
		},
		{
			ID: "policy-resource", Name: "Network resource access", Enabled: true,
			Rules: []*types.PolicyRule{{
				ID: "rule-resource", Name: "Source -> Resource", Enabled: true,
				Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
				Sources:             []string{"group-src"},
				DestinationResource: types.Resource{ID: "resource-1"},
			}},
		},
	}

	routes := map[route.ID]*route.Route{
		"route-main": {
			ID: "route-main", Network: netip.MustParsePrefix("192.168.10.0/24"),
			Peer: peers["peer-dst-1"].Key, PeerID: "peer-dst-1",
			Enabled: true, Metric: 100,
			Groups: []string{"group-src", "group-dst"}, PeerGroups: []string{"group-dst"},
		},
	}

	users := map[string]*types.User{
		"user-1": {Id: "user-1", Role: types.UserRoleAdmin, IsServiceUser: false, AutoGroups: []string{"group-all"}},
		"user-2": {Id: "user-2", Role: types.UserRoleUser, IsServiceUser: false, AutoGroups: []string{"group-all"}},
	}

	account := &types.Account{
		Id: "account-components-test", Peers: peers, Groups: groups, Policies: policies, Routes: routes,
		Users: users,
		Network: &types.Network{
			Identifier: "net-test", Net: net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(16, 32)}, Serial: 1,
		},
		DNSSettings: types.DNSSettings{DisabledManagementGroups: []string{"group-dst"}},
		NameServerGroups: map[string]*nbdns.NameServerGroup{
			"ns-main": {
				ID: "ns-main", Name: "Main NS", Enabled: true, Groups: []string{"group-src"},
				NameServers: []nbdns.NameServer{{IP: netip.MustParseAddr("8.8.8.8"), NSType: nbdns.UDPNameServerType, Port: 53}},
			},
		},
		PostureChecks: []*posture.Checks{},
		NetworkResources: []*resourceTypes.NetworkResource{
			{
				ID: "resource-1", NetworkID: "net-1", AccountID: "account-components-test", Enabled: true,
				Type: resourceTypes.Host, Prefix: netip.MustParsePrefix("10.200.0.1/32"), Address: "10.200.0.1/32",
			},
		},
		Networks: []*networkTypes.Network{
			{ID: "net-1", Name: "Resource Net", AccountID: "account-components-test"},
		},
		NetworkRouters: []*routerTypes.NetworkRouter{
			{ID: "router-1", NetworkID: "net-1", Peer: "peer-router-1", Enabled: true, AccountID: "account-components-test"},
		},
		Settings: &types.Settings{PeerLoginExpirationEnabled: false, PeerLoginExpiration: 24 * time.Hour},
	}

	for _, p := range account.Policies {
		p.AccountID = account.Id
	}
	for _, r := range account.Routes {
		r.AccountID = account.Id
	}

	return account
}
