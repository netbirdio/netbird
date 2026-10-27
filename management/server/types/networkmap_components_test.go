package types_test

import (
	"context"
	"encoding/base64"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbdns "github.com/netbirdio/netbird/dns"
	nbgrpc "github.com/netbirdio/netbird/management/internals/shared/grpc"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
	"github.com/netbirdio/netbird/shared/management/networkmap"
	"github.com/netbirdio/netbird/shared/management/networkmap/nmdata"
	"github.com/netbirdio/netbird/shared/management/proto"
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

func peerIDs(peers []*nmdata.Peer) []string {
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

	assert.NotContains(t, peerIDs(nm.OfflinePeers), "peer-dst-1", "expired peer should NOT be in OfflinePeers")
	assert.NotContains(t, peerIDs(nm.Peers), "peer-dst-1", "expired peer should NOT be in active Peers")
}

func TestNetworkMapComponents_LoginExpiredFlag(t *testing.T) {
	account := createComponentTestAccount()
	account.Settings.PeerLoginExpirationEnabled = false
	account.Peers["peer-dst-1"].Status.LoginExpired = true

	nm := networkMapFromComponents(t, account, "peer-src-1", allPeersValidated(account))

	assert.NotContains(t, peerIDs(nm.OfflinePeers), "peer-dst-1", "peer flagged login-expired should NOT be in OfflinePeers")
	assert.NotContains(t, peerIDs(nm.Peers), "peer-dst-1", "peer flagged login-expired should NOT be in active Peers")
}

func TestNetworkMapComponents_LoginExpiredResourceSourcePeer(t *testing.T) {
	account := createComponentTestAccount()
	account.Peers["peer-src-2"].Status.LoginExpired = true

	nm := networkMapFromComponents(t, account, "peer-router-1", allPeersValidated(account))

	assert.NotContains(t, peerIDs(nm.Peers), "peer-src-2", "expired resource source peer should NOT be in the router's Peers")
	assert.NotContains(t, peerIDs(nm.OfflinePeers), "peer-src-2", "expired resource source peer should NOT be in OfflinePeers")
	assert.Contains(t, peerIDs(nm.Peers), "peer-src-1", "valid resource source peer should stay in the router's Peers")

	expiredRange := account.Peers["peer-src-2"].IP.String() + "/32"
	validRange := account.Peers["peer-src-1"].IP.String() + "/32"
	var sources []string
	for _, rule := range nm.RoutesFirewallRules {
		sources = append(sources, rule.SourceRanges...)
	}
	assert.NotContains(t, sources, expiredRange, "expired peer should not be a route firewall rule source")
	assert.Contains(t, sources, validRange, "valid peer should remain a route firewall rule source")
}

func TestNetworkMapComponents_LoginExpiredRoutingPeerIsDropped(t *testing.T) {
	account := createComponentTestAccount()
	account.Settings.PeerLoginExpirationEnabled = false
	account.Peers["peer-router-1"].Status.LoginExpired = true
	account.Groups["group-src"].Peers = append(account.Groups["group-src"].Peers, "peer-router-1")

	nm := networkMapFromComponents(t, account, "peer-src-1", allPeersValidated(account))

	assert.NotContains(t, peerIDs(nm.OfflinePeers), "peer-router-1", "expired routing peer should NOT be in OfflinePeers")
	assert.NotContains(t, peerIDs(nm.Peers), "peer-router-1", "expired routing peer should NOT be in active Peers")

	routerNM := networkMapFromComponents(t, account, "peer-router-1", allPeersValidated(account))
	routerRange := account.Peers["peer-router-1"].IP.String() + "/32"
	for _, rule := range nm.RoutesFirewallRules {
		assert.NotContains(t, rule.SourceRanges, routerRange, "expired routing peer should not be a route firewall rule source")
	}
	assert.NotContains(t, peerIDs(routerNM.Peers), "peer-router-1")
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

// A receiver without a firewall asks Calculate to skip the route firewall
// rules. Everything the rest of the sync consumes — routes, peers, peer
// firewall rules — must come out unchanged.
func TestNetworkMapComponents_SkipRouteFirewallRules(t *testing.T) {
	ctx := context.Background()
	account := createComponentTestAccount()

	// The shared fixture leaves peer-router-1 out of every peer ACL, so its
	// FirewallRules would be empty and the comparison below vacuous. Give the
	// router a policy of its own.
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-router", Name: "Router connectivity", Enabled: true,
		Rules: []*types.PolicyRule{{
			ID: "rule-router", Name: "Allow all <-> router", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
			Bidirectional: true,
			Sources:       []string{"group-all"}, Destinations: []string{"group-all"},
		}},
	})

	validated := allPeersValidated(account)

	components := account.GetPeerNetworkMapComponents(
		ctx,
		"peer-router-1",
		account.GetPeersCustomZone(ctx, "netbird.io"),
		nil,
		validated,
		account.GetResourcePoliciesMap(),
		account.GetResourceRoutersMap(),
		account.GetActiveGroupUsers(),
	)

	full := components.Calculate(ctx)
	require.NotEmpty(t, full.RoutesFirewallRules, "baseline: router peer must get route firewall rules")
	require.NotEmpty(t, full.FirewallRules, "baseline: router peer must get peer firewall rules")

	components.SkipRouteFirewallRules = true
	skipped := components.Calculate(ctx)

	assert.Empty(t, skipped.RoutesFirewallRules, "route firewall rules must not be computed when skipped")
	assert.ElementsMatch(t, routeNetworks(full.Routes), routeNetworks(skipped.Routes),
		"skipping route firewall rules must not change the routes")
	assert.ElementsMatch(t, peerIDs(full.Peers), peerIDs(skipped.Peers),
		"skipping route firewall rules must not change the peers to connect")
	assert.Equal(t, full.FirewallRules, skipped.FirewallRules,
		"peer firewall rules are unrelated and must come out unchanged")
}

func routeNetworks(routes []*nmdata.Route) []string {
	networks := make([]string, 0, len(routes))
	for _, r := range routes {
		networks = append(networks, r.Network.String())
	}
	return networks
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

func TestNetworkMapComponents_SSHAuthorizedUserBlocked(t *testing.T) {
	account := createComponentTestAccount()
	account.Peers["peer-dst-1"].SSHEnabled = true
	account.Users["user-2"].Blocked = true

	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-ssh-temp", Name: "Temporary SSH", Enabled: true, AccountID: account.Id,
		Rules: []*types.PolicyRule{
			{
				ID: "rule-ssh-blocked", Name: "SSH blocked user", Enabled: true,
				Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolNetbirdSSH,
				Sources: []string{"group-src"}, Destinations: []string{"group-dst"},
				AuthorizedUser: "user-2",
			},
			{
				ID: "rule-ssh-active", Name: "SSH active user", Enabled: true,
				Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolNetbirdSSH,
				Sources: []string{"group-src"}, Destinations: []string{"group-dst"},
				AuthorizedUser: "user-1",
			},
		},
	})

	nm := networkMapFromComponents(t, account, "peer-dst-1", allPeersValidated(account))

	assert.Contains(t, nm.AuthorizedUsers["*"], "user-1", "active authorized user should be allowed")
	assert.NotContains(t, nm.AuthorizedUsers["*"], "user-2", "blocked authorized user must not be allowed")
	assert.True(t, nm.EnableSSH, "the active user's rule enables SSH")

	t.Run("blocked user rule alone does not enable SSH", func(t *testing.T) {
		account.Policies = []*types.Policy{sshPolicy(account.Id, &types.PolicyRule{
			ID: "rule-ssh-only-blocked", Action: types.PolicyTrafficActionAccept, AuthorizedUser: "user-2",
		})}

		nm := networkMapFromComponents(t, account, "peer-dst-1", allPeersValidated(account))

		assert.False(t, nm.EnableSSH, "a blocked-user rule must not enable SSH")
		assert.Empty(t, nm.AuthorizedUsers)
	})
}

func sshPolicy(accountID string, rule *types.PolicyRule) *types.Policy {
	rule.Enabled = true
	rule.Protocol = types.PolicyRuleProtocolNetbirdSSH
	rule.Sources = []string{"group-src"}
	rule.Destinations = []string{"group-dst"}
	return &types.Policy{ID: "policy-" + rule.ID, Name: rule.ID, Enabled: true, AccountID: accountID, Rules: []*types.PolicyRule{rule}}
}

func TestNetworkMapComponents_DropSSHRuleDoesNotEnableSSH(t *testing.T) {
	cases := map[string]*types.PolicyRule{
		"no authorized groups":    {ID: "rule-drop-all", Action: types.PolicyTrafficActionDrop},
		"authorized groups":       {ID: "rule-drop-groups", Action: types.PolicyTrafficActionDrop, AuthorizedGroups: map[string][]string{"group-all": {"root"}}},
		"authorized user":         {ID: "rule-drop-user", Action: types.PolicyTrafficActionDrop, AuthorizedUser: "user-1"},
		"legacy drop tcp port 22": {ID: "rule-drop-legacy", Action: types.PolicyTrafficActionDrop},
	}
	for name, rule := range cases {
		t.Run(name, func(t *testing.T) {
			account := createComponentTestAccount()
			account.Peers["peer-dst-1"].SSHEnabled = true
			p := sshPolicy(account.Id, rule)
			if name == "legacy drop tcp port 22" {
				rule.Protocol = types.PolicyRuleProtocolTCP
				rule.Ports = []string{"22"}
			}
			account.Policies = []*types.Policy{p}

			nm := networkMapFromComponents(t, account, "peer-dst-1", allPeersValidated(account))

			assert.False(t, nm.EnableSSH, "drop rule must not enable SSH")
			assert.Empty(t, nm.AuthorizedUsers, "drop rule must not authorize users")
			assert.False(t, types.PeerSSHEnabledFromPolicies([]*types.Policy{p}, "peer-dst-1", map[string]struct{}{"group-dst": {}}, true),
				"PeerSSHEnabledFromPolicies must ignore drop rules")
		})
	}
}

func TestNetworkMapComponents_SSHRuleWithoutPortsIsPort22(t *testing.T) {
	account := createComponentTestAccount()
	account.Peers["peer-dst-1"].SSHEnabled = true
	account.Policies = append(account.Policies, sshPolicy(account.Id, &types.PolicyRule{
		ID: "rule-ssh-noports", Action: types.PolicyTrafficActionAccept,
	}))

	nm := networkMapFromComponents(t, account, "peer-dst-1", allPeersValidated(account))

	srcIP := account.Peers["peer-src-1"].IP.String()
	var ports []string
	for _, fr := range nm.FirewallRules {
		if fr.PolicyID == "rule-ssh-noports" && fr.PeerIP == srcIP && fr.Direction == types.FirewallRuleDirectionIN {
			assert.Equal(t, "tcp", fr.Protocol)
			assert.NotEmpty(t, fr.Port, "port-less netbird-ssh rule must not open all TCP ports")
			ports = append(ports, fr.Port)
		}
	}
	assert.Contains(t, ports, "22")
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
		if r.NetworkType == int(route.DomainNetwork) && len(r.Domains) > 0 && r.Domains[0].SafeString() == "api.example.com" {
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
			ID: "peer-src-1", IP: netip.AddrFrom4([4]byte{100, 64, 0, 1}), Key: "key-src-1", DNSLabel: "src1",
			Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()}, UserID: "user-1",
			Meta: nbpeer.PeerSystemMeta{WtVersion: "0.35.0", GoOS: "linux"},
		},
		"peer-src-2": {
			ID: "peer-src-2", IP: netip.AddrFrom4([4]byte{100, 64, 0, 2}), Key: "key-src-2", DNSLabel: "src2",
			Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()}, UserID: "user-1",
			Meta: nbpeer.PeerSystemMeta{WtVersion: "0.35.0", GoOS: "linux"},
		},
		"peer-dst-1": {
			ID: "peer-dst-1", IP: netip.AddrFrom4([4]byte{100, 64, 0, 3}), Key: "key-dst-1", DNSLabel: "dst1",
			Status: &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()}, UserID: "user-2",
			Meta: nbpeer.PeerSystemMeta{WtVersion: "0.35.0", GoOS: "linux"},
		},
		"peer-router-1": {
			ID: "peer-router-1", IP: netip.AddrFrom4([4]byte{100, 64, 0, 10}), Key: "key-router-1", DNSLabel: "router1",
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

func envelopeAccountWithWgKeys(account *types.Account) {
	for id, p := range account.Peers {
		raw := make([]byte, 32)
		copy(raw, id)
		p.Key = base64.StdEncoding.EncodeToString(raw)
	}
	for _, r := range account.Routes {
		r.Peer = r.PeerID
	}
}

func envelopeForPeer(t *testing.T, account *types.Account, peerID string) *proto.NetworkMapEnvelope {
	t.Helper()
	components := account.GetPeerNetworkMapComponents(
		context.Background(), peerID, account.GetPeersCustomZone(context.Background(), "netbird.io"), nil,
		allPeersValidated(account), account.GetResourcePoliciesMap(), account.GetResourceRoutersMap(), account.GetActiveGroupUsers(),
	)
	env := nbgrpc.EncodeNetworkMapEnvelope(nbgrpc.ComponentsEnvelopeInput{Components: components, DNSDomain: "netbird.io"})
	require.NotNil(t, env.GetFull())
	return env
}

func envelopeHasPeer(full *proto.NetworkMapComponentsFull, label string) bool {
	for _, p := range full.Peers {
		if p.DnsLabel == label {
			return true
		}
	}
	return false
}

func TestNetworkMapEnvelope_LoginExpiredPeerAndRouteDropped(t *testing.T) {
	account := createComponentTestAccount()
	envelopeAccountWithWgKeys(account)
	account.Settings.PeerLoginExpirationEnabled = false
	account.Peers["peer-dst-1"].Status.LoginExpired = true
	account.Routes["route-direct"] = &route.Route{
		ID: "route-direct", AccountID: account.Id, Network: netip.MustParsePrefix("192.168.20.0/24"),
		Peer: "peer-dst-1", PeerID: "peer-dst-1", Enabled: true, Metric: 100,
		Groups: []string{"group-src"},
	}

	env := envelopeForPeer(t, account, "peer-src-1")
	full := env.GetFull()

	assert.False(t, envelopeHasPeer(full, "dst1"), "flagged peer must not be in the envelope peer table")
	assert.True(t, envelopeHasPeer(full, "src1"), "target peer must stay")
	assert.True(t, envelopeHasPeer(full, "router1"), "valid peers must stay")
	for _, r := range full.Routes {
		assert.NotEqual(t, "192.168.20.0/24", r.NetworkCidr, "route bound to the flagged peer must not be shipped")
		assert.False(t, r.PeerIndexSet, "no shipped route may point at a peer")
	}
	for _, g := range full.Groups {
		for _, idx := range g.PeerIndexes {
			assert.NotEqual(t, "dst1", full.Peers[idx].DnsLabel, "group must not reference the flagged peer")
		}
	}

	res, err := networkmap.EnvelopeToNetworkMap(context.Background(), env, account.Peers["peer-src-1"].Key, "netbird.io", false)
	require.NoError(t, err)
	for _, rp := range res.NetworkMap.RemotePeers {
		assert.NotEqual(t, account.Peers["peer-dst-1"].Key, rp.WgPubKey, "client must not receive the flagged peer")
	}
	assert.Empty(t, res.NetworkMap.OfflinePeers)
	for _, r := range res.NetworkMap.Routes {
		assert.NotEqual(t, account.Peers["peer-dst-1"].Key, r.Peer, "client must not compute a route through the flagged peer")
	}
}

func TestNetworkMapEnvelope_LoginExpiredRouterPeerDropped(t *testing.T) {
	account := createComponentTestAccount()
	envelopeAccountWithWgKeys(account)
	account.Peers["peer-router-1"].Status.LoginExpired = true

	full := envelopeForPeer(t, account, "peer-src-1").GetFull()

	assert.False(t, envelopeHasPeer(full, "router1"), "flagged routing peer must not be in the envelope peer table")
	assert.Empty(t, full.RouterPeerIndexes)
	for _, list := range full.RoutersMap {
		assert.Empty(t, list.Entries, "no router entry may remain for the flagged routing peer")
	}
}
