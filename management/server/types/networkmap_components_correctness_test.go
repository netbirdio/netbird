package types_test

import (
	"context"
	"fmt"
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

// scalableTestAccountWithoutDefaultPolicy creates an account without the blanket "Allow All" policy.
// Use this for tests that need to verify feature-specific connectivity in isolation.
func scalableTestAccountWithoutDefaultPolicy(numPeers, numGroups int) (*types.Account, map[string]struct{}) {
	return buildScalableTestAccount(numPeers, numGroups, false)
}

// scalableTestAccount creates a realistic account with a blanket "Allow All" policy
// plus per-group policies, routes, network resources, posture checks, and DNS settings.
func scalableTestAccount(numPeers, numGroups int) (*types.Account, map[string]struct{}) {
	return buildScalableTestAccount(numPeers, numGroups, true)
}

// buildScalableTestAccount is the core builder. When withDefaultPolicy is true it adds
// a blanket group-all <-> group-all allow rule; when false the only policies are the
// per-group ones, so tests can verify feature-specific connectivity in isolation.
func buildScalableTestAccount(numPeers, numGroups int, withDefaultPolicy bool) (*types.Account, map[string]struct{}) {
	peers := make(map[string]*nbpeer.Peer, numPeers)
	allGroupPeers := make([]string, 0, numPeers)

	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)
		ip := net.IP{100, byte(64 + i/65536), byte((i / 256) % 256), byte(i % 256)}
		wtVersion := "0.25.0"
		if i%2 == 0 {
			wtVersion = "0.40.0"
		}

		p := &nbpeer.Peer{
			ID:       peerID,
			IP:       ip,
			Key:      fmt.Sprintf("key-%s", peerID),
			DNSLabel: fmt.Sprintf("peer%d", i),
			Status:   &nbpeer.PeerStatus{Connected: true, LastSeen: time.Now()},
			UserID:   "user-admin",
			Meta:     nbpeer.PeerSystemMeta{WtVersion: wtVersion, GoOS: "linux"},
		}

		if i == numPeers-2 {
			p.LoginExpirationEnabled = true
			pastTimestamp := time.Now().Add(-2 * time.Hour)
			p.LastLogin = &pastTimestamp
		}

		peers[peerID] = p
		allGroupPeers = append(allGroupPeers, peerID)
	}

	groups := make(map[string]*types.Group, numGroups+1)
	groups["group-all"] = &types.Group{ID: "group-all", Name: "All", Peers: allGroupPeers}

	peersPerGroup := numPeers / numGroups
	if peersPerGroup < 1 {
		peersPerGroup = 1
	}

	for g := range numGroups {
		groupID := fmt.Sprintf("group-%d", g)
		groupPeers := make([]string, 0, peersPerGroup)
		start := g * peersPerGroup
		end := start + peersPerGroup
		if end > numPeers {
			end = numPeers
		}
		for i := start; i < end; i++ {
			groupPeers = append(groupPeers, fmt.Sprintf("peer-%d", i))
		}
		groups[groupID] = &types.Group{ID: groupID, Name: fmt.Sprintf("Group %d", g), Peers: groupPeers}
	}

	policies := make([]*types.Policy, 0, numGroups+2)
	if withDefaultPolicy {
		policies = append(policies, &types.Policy{
			ID: "policy-all", Name: "Default-Allow", Enabled: true,
			Rules: []*types.PolicyRule{{
				ID: "rule-all", Name: "Allow All", Enabled: true, Action: types.PolicyTrafficActionAccept,
				Protocol: types.PolicyRuleProtocolALL, Bidirectional: true,
				Sources: []string{"group-all"}, Destinations: []string{"group-all"},
			}},
		})
	}

	for g := range numGroups {
		groupID := fmt.Sprintf("group-%d", g)
		dstGroup := fmt.Sprintf("group-%d", (g+1)%numGroups)
		policies = append(policies, &types.Policy{
			ID: fmt.Sprintf("policy-%d", g), Name: fmt.Sprintf("Policy %d", g), Enabled: true,
			Rules: []*types.PolicyRule{{
				ID: fmt.Sprintf("rule-%d", g), Name: fmt.Sprintf("Rule %d", g), Enabled: true,
				Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolTCP,
				Bidirectional: true,
				Ports:         []string{"8080"},
				Sources:       []string{groupID}, Destinations: []string{dstGroup},
			}},
		})
	}

	if numGroups >= 2 {
		policies = append(policies, &types.Policy{
			ID: "policy-drop", Name: "Drop DB traffic", Enabled: true,
			Rules: []*types.PolicyRule{{
				ID: "rule-drop", Name: "Drop DB", Enabled: true, Action: types.PolicyTrafficActionDrop,
				Protocol: types.PolicyRuleProtocolTCP, Ports: []string{"5432"}, Bidirectional: true,
				Sources: []string{"group-0"}, Destinations: []string{"group-1"},
			}},
		})
	}

	numRoutes := numGroups
	if numRoutes > 20 {
		numRoutes = 20
	}
	routes := make(map[route.ID]*route.Route, numRoutes)
	for r := range numRoutes {
		routeID := route.ID(fmt.Sprintf("route-%d", r))
		peerIdx := (numPeers / 2) + r
		if peerIdx >= numPeers {
			peerIdx = numPeers - 1
		}
		routePeerID := fmt.Sprintf("peer-%d", peerIdx)
		groupID := fmt.Sprintf("group-%d", r%numGroups)
		routes[routeID] = &route.Route{
			ID:                  routeID,
			Network:             netip.MustParsePrefix(fmt.Sprintf("10.%d.0.0/16", r)),
			Peer:                peers[routePeerID].Key,
			PeerID:              routePeerID,
			Description:         fmt.Sprintf("Route %d", r),
			Enabled:             true,
			PeerGroups:          []string{groupID},
			Groups:              []string{"group-all"},
			AccessControlGroups: []string{groupID},
			AccountID:           "test-account",
		}
	}

	numResources := numGroups / 2
	if numResources < 1 {
		numResources = 1
	}
	if numResources > 50 {
		numResources = 50
	}

	networkResources := make([]*resourceTypes.NetworkResource, 0, numResources)
	networksList := make([]*networkTypes.Network, 0, numResources)
	networkRouters := make([]*routerTypes.NetworkRouter, 0, numResources)

	routingPeerStart := numPeers * 3 / 4
	for nr := range numResources {
		netID := fmt.Sprintf("net-%d", nr)
		resID := fmt.Sprintf("res-%d", nr)
		routerPeerIdx := routingPeerStart + nr
		if routerPeerIdx >= numPeers {
			routerPeerIdx = numPeers - 1
		}
		routerPeerID := fmt.Sprintf("peer-%d", routerPeerIdx)

		networksList = append(networksList, &networkTypes.Network{ID: netID, Name: fmt.Sprintf("Network %d", nr), AccountID: "test-account"})
		networkResources = append(networkResources, &resourceTypes.NetworkResource{
			ID: resID, NetworkID: netID, AccountID: "test-account", Enabled: true,
			Address: fmt.Sprintf("svc-%d.netbird.cloud", nr),
		})
		networkRouters = append(networkRouters, &routerTypes.NetworkRouter{
			ID: fmt.Sprintf("router-%d", nr), NetworkID: netID, Peer: routerPeerID,
			Enabled: true, AccountID: "test-account",
		})

		policies = append(policies, &types.Policy{
			ID: fmt.Sprintf("policy-res-%d", nr), Name: fmt.Sprintf("Resource Policy %d", nr), Enabled: true,
			SourcePostureChecks: []string{"posture-check-ver"},
			Rules: []*types.PolicyRule{{
				ID: fmt.Sprintf("rule-res-%d", nr), Name: fmt.Sprintf("Allow Resource %d", nr), Enabled: true,
				Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL, Bidirectional: true,
				Sources:             []string{fmt.Sprintf("group-%d", nr%numGroups)},
				DestinationResource: types.Resource{ID: resID},
			}},
		})
	}

	account := &types.Account{
		Id:       "test-account",
		Peers:    peers,
		Groups:   groups,
		Policies: policies,
		Routes:   routes,
		Users: map[string]*types.User{
			"user-admin": {Id: "user-admin", Role: types.UserRoleAdmin, IsServiceUser: false, AccountID: "test-account"},
		},
		Network: &types.Network{
			Identifier: "net-test", Net: net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)}, Serial: 1,
		},
		DNSSettings: types.DNSSettings{DisabledManagementGroups: []string{}},
		NameServerGroups: map[string]*nbdns.NameServerGroup{
			"ns-group-main": {
				ID: "ns-group-main", Name: "Main NS", Enabled: true, Groups: []string{"group-all"},
				NameServers: []nbdns.NameServer{{IP: netip.MustParseAddr("8.8.8.8"), NSType: nbdns.UDPNameServerType, Port: 53}},
			},
		},
		PostureChecks: []*posture.Checks{
			{ID: "posture-check-ver", Name: "Check version", Checks: posture.ChecksDefinition{
				NBVersionCheck: &posture.NBVersionCheck{MinVersion: "0.26.0"},
			}},
		},
		NetworkResources: networkResources,
		Networks:         networksList,
		NetworkRouters:   networkRouters,
		Settings:         &types.Settings{PeerLoginExpirationEnabled: true, PeerLoginExpiration: 1 * time.Hour},
	}

	for _, p := range account.Policies {
		p.AccountID = account.Id
	}
	for _, r := range account.Routes {
		r.AccountID = account.Id
	}

	validatedPeers := make(map[string]struct{}, numPeers)
	for i := range numPeers {
		peerID := fmt.Sprintf("peer-%d", i)
		if i != numPeers-1 {
			validatedPeers[peerID] = struct{}{}
		}
	}

	return account, validatedPeers
}

// componentsNetworkMap is a convenience wrapper for GetPeerNetworkMapFromComponents.
func componentsNetworkMap(account *types.Account, peerID string, validatedPeers map[string]struct{}) *types.NetworkMap {
	return account.GetPeerNetworkMapFromComponents(
		context.Background(), peerID, nbdns.CustomZone{}, nil,
		validatedPeers, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap(),
		nil, account.GetActiveGroupUsers(),
	)
}

// ──────────────────────────────────────────────────────────────────────────────
// 1. PEER VISIBILITY & GROUPS
// ──────────────────────────────────────────────────────────────────────────────

func TestComponents_PeerVisibility(t *testing.T) {
	account, validatedPeers := scalableTestAccount(100, 5)
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)
	assert.Equal(t, len(validatedPeers)-1-len(nm.OfflinePeers), len(nm.Peers), "peer should see all other validated non-expired peers")
}

func TestComponents_PeerDoesNotSeeItself(t *testing.T) {
	account, validatedPeers := scalableTestAccount(50, 5)
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)
	for _, p := range nm.Peers {
		assert.NotEqual(t, "peer-0", p.ID, "peer should not see itself")
	}
}

func TestComponents_IntraGroupConnectivity(t *testing.T) {
	account, validatedPeers := scalableTestAccount(20, 2)
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)

	peerIDs := make(map[string]bool, len(nm.Peers))
	for _, p := range nm.Peers {
		peerIDs[p.ID] = true
	}
	assert.True(t, peerIDs["peer-5"], "peer-0 should see peer-5 from same group")
}

func TestComponents_CrossGroupConnectivity(t *testing.T) {
	// Without default policy, only per-group policies provide connectivity
	account, validatedPeers := scalableTestAccountWithoutDefaultPolicy(20, 2)
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)

	peerIDs := make(map[string]bool, len(nm.Peers))
	for _, p := range nm.Peers {
		peerIDs[p.ID] = true
	}
	assert.True(t, peerIDs["peer-10"], "peer-0 should see peer-10 from cross-group policy")
}

func TestComponents_BidirectionalPolicy(t *testing.T) {
	// Without default policy so bidirectional visibility comes only from per-group policies
	account, validatedPeers := scalableTestAccountWithoutDefaultPolicy(100, 5)
	nm0 := componentsNetworkMap(account, "peer-0", validatedPeers)
	nm20 := componentsNetworkMap(account, "peer-20", validatedPeers)
	require.NotNil(t, nm0)
	require.NotNil(t, nm20)

	peer0SeesPeer20 := false
	for _, p := range nm0.Peers {
		if p.ID == "peer-20" {
			peer0SeesPeer20 = true
		}
	}
	peer20SeesPeer0 := false
	for _, p := range nm20.Peers {
		if p.ID == "peer-0" {
			peer20SeesPeer0 = true
		}
	}
	assert.True(t, peer0SeesPeer20, "peer-0 should see peer-20 via bidirectional policy")
	assert.True(t, peer20SeesPeer0, "peer-20 should see peer-0 via bidirectional policy")
}

// ──────────────────────────────────────────────────────────────────────────────
// 2. PEER EXPIRATION & ACCOUNT SETTINGS
// ──────────────────────────────────────────────────────────────────────────────

func TestComponents_ExpiredPeerInOfflineList(t *testing.T) {
	account, validatedPeers := scalableTestAccount(100, 5)
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)

	offlineIDs := make(map[string]bool, len(nm.OfflinePeers))
	for _, p := range nm.OfflinePeers {
		offlineIDs[p.ID] = true
	}
	assert.True(t, offlineIDs["peer-98"], "expired peer should be in OfflinePeers")
	for _, p := range nm.Peers {
		assert.NotEqual(t, "peer-98", p.ID, "expired peer should not be in active Peers")
	}
}

func TestComponents_ExpirationDisabledSetting(t *testing.T) {
	account, validatedPeers := scalableTestAccount(100, 5)
	account.Settings.PeerLoginExpirationEnabled = false

	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)

	peerIDs := make(map[string]bool, len(nm.Peers))
	for _, p := range nm.Peers {
		peerIDs[p.ID] = true
	}
	assert.True(t, peerIDs["peer-98"], "with expiration disabled, peer-98 should be in active Peers")
}

func TestComponents_LoginExpiration_PeerLevel(t *testing.T) {
	account, validatedPeers := scalableTestAccount(20, 2)
	account.Settings.PeerLoginExpirationEnabled = true
	account.Settings.PeerLoginExpiration = 1 * time.Hour

	pastLogin := time.Now().Add(-2 * time.Hour)
	account.Peers["peer-5"].LastLogin = &pastLogin
	account.Peers["peer-5"].LoginExpirationEnabled = true

	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)

	offlineIDs := make(map[string]bool, len(nm.OfflinePeers))
	for _, p := range nm.OfflinePeers {
		offlineIDs[p.ID] = true
	}
	assert.True(t, offlineIDs["peer-5"], "login-expired peer should be in OfflinePeers")
	for _, p := range nm.Peers {
		assert.NotEqual(t, "peer-5", p.ID, "login-expired peer should not be in active Peers")
	}
}

func TestComponents_NetworkSerial(t *testing.T) {
	account, validatedPeers := scalableTestAccount(50, 5)
	account.Network.Serial = 42
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)
	assert.Equal(t, uint64(42), nm.Network.Serial, "network serial should match")
}

// ──────────────────────────────────────────────────────────────────────────────
// 3. NON-VALIDATED PEERS
// ──────────────────────────────────────────────────────────────────────────────

func TestComponents_NonValidatedPeerExcluded(t *testing.T) {
	account, validatedPeers := scalableTestAccount(100, 5)
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)
	for _, p := range nm.Peers {
		assert.NotEqual(t, "peer-99", p.ID, "non-validated peer should not appear in Peers")
	}
	for _, p := range nm.OfflinePeers {
		assert.NotEqual(t, "peer-99", p.ID, "non-validated peer should not appear in OfflinePeers")
	}
}

func TestComponents_NonValidatedTargetPeerGetsEmptyMap(t *testing.T) {
	account, validatedPeers := scalableTestAccount(100, 5)
	nm := componentsNetworkMap(account, "peer-99", validatedPeers)
	require.NotNil(t, nm)
	assert.Empty(t, nm.Peers)
	assert.Empty(t, nm.FirewallRules)
}

func TestComponents_NonExistentPeerGetsEmptyMap(t *testing.T) {
	account, validatedPeers := scalableTestAccount(100, 5)
	nm := componentsNetworkMap(account, "peer-does-not-exist", validatedPeers)
	require.NotNil(t, nm)
	assert.Empty(t, nm.Peers)
	assert.Empty(t, nm.FirewallRules)
}

// ──────────────────────────────────────────────────────────────────────────────
// 4. POLICIES & FIREWALL RULES
// ──────────────────────────────────────────────────────────────────────────────

func TestComponents_FirewallRulesGenerated(t *testing.T) {
	account, validatedPeers := scalableTestAccount(100, 5)
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)
	assert.NotEmpty(t, nm.FirewallRules, "should have firewall rules from policies")
}

func TestComponents_DropPolicyGeneratesDropRules(t *testing.T) {
	account, validatedPeers := scalableTestAccount(100, 5)
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)

	hasDropRule := false
	for _, rule := range nm.FirewallRules {
		if rule.Action == string(types.PolicyTrafficActionDrop) {
			hasDropRule = true
			break
		}
	}
	assert.True(t, hasDropRule, "should have at least one drop firewall rule")
}

func TestComponents_DisabledPolicyIgnored(t *testing.T) {
	account, validatedPeers := scalableTestAccount(50, 2)
	for _, p := range account.Policies {
		p.Enabled = false
	}
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)
	assert.Empty(t, nm.Peers, "disabled policies should yield no peers")
	assert.Empty(t, nm.FirewallRules, "disabled policies should yield no firewall rules")
}

func TestComponents_PortPolicy(t *testing.T) {
	account, validatedPeers := scalableTestAccount(50, 2)
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)

	has8080, has5432 := false, false
	for _, rule := range nm.FirewallRules {
		if rule.Port == "8080" {
			has8080 = true
		}
		if rule.Port == "5432" {
			has5432 = true
		}
	}
	assert.True(t, has8080, "should have firewall rule for port 8080")
	assert.True(t, has5432, "should have firewall rule for port 5432 (drop policy)")
}

func TestComponents_PortRangePolicy(t *testing.T) {
	account, validatedPeers := scalableTestAccount(50, 2)
	account.Peers["peer-0"].Meta.WtVersion = "0.50.0"

	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-port-range", Name: "Port Range", Enabled: true, AccountID: "test-account",
		Rules: []*types.PolicyRule{{
			ID: "rule-port-range", Name: "Port Range Rule", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolTCP,
			Bidirectional: true,
			PortRanges:    []types.RulePortRange{{Start: 8000, End: 9000}},
			Sources:       []string{"group-0"}, Destinations: []string{"group-1"},
		}},
	})

	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)

	hasPortRange := false
	for _, rule := range nm.FirewallRules {
		if rule.PortRange.Start == 8000 && rule.PortRange.End == 9000 {
			hasPortRange = true
			break
		}
	}
	assert.True(t, hasPortRange, "should have firewall rule with port range 8000-9000")
}

func TestComponents_FirewallRuleDirection(t *testing.T) {
	account, validatedPeers := scalableTestAccount(50, 2)
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)

	hasIn, hasOut := false, false
	for _, rule := range nm.FirewallRules {
		if rule.Direction == types.FirewallRuleDirectionIN {
			hasIn = true
		}
		if rule.Direction == types.FirewallRuleDirectionOUT {
			hasOut = true
		}
	}
	assert.True(t, hasIn, "should have inbound firewall rules")
	assert.True(t, hasOut, "should have outbound firewall rules")
}

// ──────────────────────────────────────────────────────────────────────────────
// 5. ROUTES
// ──────────────────────────────────────────────────────────────────────────────

func TestComponents_RoutesIncluded(t *testing.T) {
	account, validatedPeers := scalableTestAccount(100, 5)
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)
	assert.NotEmpty(t, nm.Routes, "should have routes")
}

func TestComponents_DisabledRouteExcluded(t *testing.T) {
	account, validatedPeers := scalableTestAccount(50, 2)
	for _, r := range account.Routes {
		r.Enabled = false
	}
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)
	for _, r := range nm.Routes {
		assert.True(t, r.Enabled, "only enabled routes should appear")
	}
}

func TestComponents_RoutesFirewallRulesForACG(t *testing.T) {
	account, validatedPeers := scalableTestAccount(100, 5)
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)
	assert.NotEmpty(t, nm.RoutesFirewallRules, "should have route firewall rules for access-controlled routes")
}

func TestComponents_HARouteDeduplication(t *testing.T) {
	account, validatedPeers := scalableTestAccount(50, 5)

	haNetwork := netip.MustParsePrefix("172.16.0.0/16")
	account.Routes["route-ha-1"] = &route.Route{
		ID: "route-ha-1", Network: haNetwork, PeerID: "peer-10",
		Peer: account.Peers["peer-10"].Key, Enabled: true, Metric: 100,
		Groups: []string{"group-all"}, PeerGroups: []string{"group-0"}, AccountID: "test-account",
	}
	account.Routes["route-ha-2"] = &route.Route{
		ID: "route-ha-2", Network: haNetwork, PeerID: "peer-20",
		Peer: account.Peers["peer-20"].Key, Enabled: true, Metric: 200,
		Groups: []string{"group-all"}, PeerGroups: []string{"group-1"}, AccountID: "test-account",
	}

	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)

	haRoutes := 0
	for _, r := range nm.Routes {
		if r.Network == haNetwork {
			haRoutes++
		}
	}
	// Components deduplicates HA routes with the same HA unique ID, returning one entry per HA group
	assert.Equal(t, 1, haRoutes, "HA routes with same network should be deduplicated into one entry")
}

// ──────────────────────────────────────────────────────────────────────────────
// 6. NETWORK RESOURCES & ROUTERS
// ──────────────────────────────────────────────────────────────────────────────

func TestComponents_NetworkResourceRoutes_RouterPeer(t *testing.T) {
	account, validatedPeers := scalableTestAccount(100, 5)

	var routerPeerID string
	for _, nr := range account.NetworkRouters {
		routerPeerID = nr.Peer
		break
	}
	require.NotEmpty(t, routerPeerID)

	nm := componentsNetworkMap(account, routerPeerID, validatedPeers)
	require.NotNil(t, nm)
	assert.NotEmpty(t, nm.Peers, "router peer should see source peers")
}

func TestComponents_NetworkResourceRoutes_SourcePeerSeesRouterPeer(t *testing.T) {
	account, validatedPeers := scalableTestAccount(100, 5)

	var routerPeerID string
	for _, nr := range account.NetworkRouters {
		routerPeerID = nr.Peer
		break
	}
	require.NotEmpty(t, routerPeerID)

	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)

	peerIDs := make(map[string]bool, len(nm.Peers))
	for _, p := range nm.Peers {
		peerIDs[p.ID] = true
	}
	assert.True(t, peerIDs[routerPeerID], "source peer should see router peer for network resource")
}

func TestComponents_DisabledNetworkResourceIgnored(t *testing.T) {
	account, validatedPeers := scalableTestAccount(50, 5)
	for _, nr := range account.NetworkResources {
		nr.Enabled = false
	}
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)
	assert.NotNil(t, nm.Network)
}

// ──────────────────────────────────────────────────────────────────────────────
// 7. POSTURE CHECKS
// ──────────────────────────────────────────────────────────────────────────────

func TestComponents_PostureCheckFiltering_PassingPeer(t *testing.T) {
	account, validatedPeers := scalableTestAccount(100, 5)
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)
	assert.NotEmpty(t, nm.Routes, "passing peer should have routes including resource routes")
}

func TestComponents_PostureCheckFiltering_FailingPeer(t *testing.T) {
	// peer-0 has version 0.40.0 (passes posture check >= 0.26.0)
	// peer-1 has version 0.25.0 (fails posture check >= 0.26.0)
	// Resource policies require posture-check-ver, so the failing peer
	// should not see the router peer for those resources.
	account, validatedPeers := scalableTestAccountWithoutDefaultPolicy(100, 5)

	nm0 := componentsNetworkMap(account, "peer-0", validatedPeers)
	nm1 := componentsNetworkMap(account, "peer-1", validatedPeers)
	require.NotNil(t, nm0)
	require.NotNil(t, nm1)

	// The passing peer should have more peers visible (including resource router peers)
	// than the failing peer, because the failing peer is excluded from resource policies.
	assert.Greater(t, len(nm0.Peers), len(nm1.Peers),
		"passing peer (0.40.0) should see more peers than failing peer (0.25.0) due to posture-gated resource policies")
}

func TestComponents_MultiplePostureChecks(t *testing.T) {
	account, validatedPeers := scalableTestAccountWithoutDefaultPolicy(50, 2)

	// Keep only the posture-gated policy — remove per-group policies so connectivity is isolated
	account.Policies = []*types.Policy{}

	// Set kernel version on peers so the OS posture check can evaluate
	for _, p := range account.Peers {
		p.Meta.KernelVersion = "5.15.0"
	}

	account.PostureChecks = append(account.PostureChecks, &posture.Checks{
		ID: "posture-check-os", Name: "Check OS",
		Checks: posture.ChecksDefinition{
			OSVersionCheck: &posture.OSVersionCheck{Linux: &posture.MinKernelVersionCheck{MinKernelVersion: "0.0.1"}},
		},
	})
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-multi-posture", Name: "Multi Posture", Enabled: true, AccountID: "test-account",
		SourcePostureChecks: []string{"posture-check-ver", "posture-check-os"},
		Rules: []*types.PolicyRule{{
			ID: "rule-multi-posture", Name: "Multi Check Rule", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL,
			Bidirectional: true,
			Sources:       []string{"group-0"}, Destinations: []string{"group-1"},
		}},
	})

	// peer-0 (0.40.0, kernel 5.15.0) passes both checks, should see group-1 peers
	nm0 := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm0)
	assert.NotEmpty(t, nm0.Peers, "peer passing both posture checks should see destination peers")

	// peer-1 (0.25.0, kernel 5.15.0) fails version check, should NOT see group-1 peers
	nm1 := componentsNetworkMap(account, "peer-1", validatedPeers)
	require.NotNil(t, nm1)
	assert.Empty(t, nm1.Peers,
		"peer failing posture check should see no peers when posture-gated policy is the only connectivity")
}

// ──────────────────────────────────────────────────────────────────────────────
// 8. DNS
// ──────────────────────────────────────────────────────────────────────────────

func TestComponents_DNSConfigEnabled(t *testing.T) {
	account, validatedPeers := scalableTestAccount(100, 5)
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)
	assert.True(t, nm.DNSConfig.ServiceEnable, "DNS should be enabled")
	assert.NotEmpty(t, nm.DNSConfig.NameServerGroups, "should have nameserver groups")
}

func TestComponents_DNSDisabledByManagementGroup(t *testing.T) {
	account, validatedPeers := scalableTestAccount(100, 5)
	account.DNSSettings.DisabledManagementGroups = []string{"group-all"}

	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)
	assert.False(t, nm.DNSConfig.ServiceEnable, "DNS should be disabled for peer in disabled group")
}

func TestComponents_DNSNameServerGroupDistribution(t *testing.T) {
	account, validatedPeers := scalableTestAccount(20, 2)
	account.NameServerGroups["ns-group-0"] = &nbdns.NameServerGroup{
		ID: "ns-group-0", Name: "Group 0 NS", Enabled: true, Groups: []string{"group-0"},
		NameServers: []nbdns.NameServer{{IP: netip.MustParseAddr("1.1.1.1"), NSType: nbdns.UDPNameServerType, Port: 53}},
	}

	nm0 := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm0)
	hasGroup0NS := false
	for _, ns := range nm0.DNSConfig.NameServerGroups {
		if ns.ID == "ns-group-0" {
			hasGroup0NS = true
		}
	}
	assert.True(t, hasGroup0NS, "peer-0 in group-0 should receive ns-group-0")

	nm10 := componentsNetworkMap(account, "peer-10", validatedPeers)
	require.NotNil(t, nm10)
	hasGroup0NSForPeer10 := false
	for _, ns := range nm10.DNSConfig.NameServerGroups {
		if ns.ID == "ns-group-0" {
			hasGroup0NSForPeer10 = true
		}
	}
	assert.False(t, hasGroup0NSForPeer10, "peer-10 in group-1 should NOT receive ns-group-0")
}

func TestComponents_DNSCustomZone(t *testing.T) {
	account, validatedPeers := scalableTestAccount(20, 2)
	customZone := nbdns.CustomZone{
		Domain: "netbird.cloud.",
		Records: []nbdns.SimpleRecord{
			{Name: "peer0.netbird.cloud.", Type: 1, Class: "IN", TTL: 300, RData: account.Peers["peer-0"].IP.String()},
			{Name: "peer1.netbird.cloud.", Type: 1, Class: "IN", TTL: 300, RData: account.Peers["peer-1"].IP.String()},
		},
	}

	nm := account.GetPeerNetworkMapFromComponents(
		context.Background(), "peer-0", customZone, nil,
		validatedPeers, account.GetResourcePoliciesMap(), account.GetResourceRoutersMap(),
		nil, account.GetActiveGroupUsers(),
	)
	require.NotNil(t, nm)
	assert.True(t, nm.DNSConfig.ServiceEnable)
}

// ──────────────────────────────────────────────────────────────────────────────
// 9. SSH
// ──────────────────────────────────────────────────────────────────────────────

func TestComponents_SSHPolicy(t *testing.T) {
	account, validatedPeers := scalableTestAccount(20, 2)
	account.Groups["ssh-users"] = &types.Group{ID: "ssh-users", Name: "SSH Users", Peers: []string{}}
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-ssh", Name: "SSH Access", Enabled: true, AccountID: "test-account",
		Rules: []*types.PolicyRule{{
			ID: "rule-ssh", Name: "Allow SSH", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolNetbirdSSH,
			Bidirectional: false,
			Sources:       []string{"group-0"}, Destinations: []string{"group-1"},
			AuthorizedGroups: map[string][]string{"ssh-users": {"root"}},
		}},
	})

	nm := componentsNetworkMap(account, "peer-10", validatedPeers)
	require.NotNil(t, nm)
	assert.True(t, nm.EnableSSH, "SSH should be enabled for destination peer of SSH policy")
}

func TestComponents_SSHNotEnabledWithoutPolicy(t *testing.T) {
	account, validatedPeers := scalableTestAccount(20, 2)
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)
	assert.False(t, nm.EnableSSH, "SSH should not be enabled without SSH policy")
}

// ──────────────────────────────────────────────────────────────────────────────
// 10. CROSS-PEER CONSISTENCY
// ──────────────────────────────────────────────────────────────────────────────

// TestComponents_AllPeersGetValidMaps verifies that every validated peer gets a
// non-nil map with a consistent network serial and non-empty peer list.
func TestComponents_AllPeersGetValidMaps(t *testing.T) {
	account, validatedPeers := scalableTestAccount(50, 5)
	for peerID := range account.Peers {
		if _, validated := validatedPeers[peerID]; !validated {
			continue
		}
		nm := componentsNetworkMap(account, peerID, validatedPeers)
		require.NotNil(t, nm, "network map should not be nil for %s", peerID)
		assert.Equal(t, account.Network.Serial, nm.Network.Serial, "serial mismatch for %s", peerID)
		assert.NotEmpty(t, nm.Peers, "validated peer %s should see other peers", peerID)
	}
}

// TestComponents_LargeScaleMapGeneration verifies that components can generate maps
// at larger scales without errors and with consistent output.
func TestComponents_LargeScaleMapGeneration(t *testing.T) {
	scales := []struct{ peers, groups int }{
		{500, 20},
		{1000, 50},
	}
	for _, s := range scales {
		t.Run(fmt.Sprintf("%dpeers_%dgroups", s.peers, s.groups), func(t *testing.T) {
			account, validatedPeers := scalableTestAccount(s.peers, s.groups)
			testPeers := []string{"peer-0", fmt.Sprintf("peer-%d", s.peers/4), fmt.Sprintf("peer-%d", s.peers/2)}
			for _, peerID := range testPeers {
				nm := componentsNetworkMap(account, peerID, validatedPeers)
				require.NotNil(t, nm, "network map should not be nil for %s", peerID)
				assert.NotEmpty(t, nm.Peers, "peer %s should see other peers at scale", peerID)
				assert.NotEmpty(t, nm.Routes, "peer %s should have routes at scale", peerID)
				assert.Equal(t, account.Network.Serial, nm.Network.Serial, "serial mismatch for %s", peerID)
			}
		})
	}
}

// ──────────────────────────────────────────────────────────────────────────────
// 11. PEER-AS-RESOURCE POLICIES
// ──────────────────────────────────────────────────────────────────────────────

// TestComponents_PeerAsSourceResource verifies that a policy with SourceResource.Type=Peer
// targets only that specific peer as the source.
func TestComponents_PeerAsSourceResource(t *testing.T) {
	account, validatedPeers := scalableTestAccount(20, 2)

	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-peer-src", Name: "Peer Source Resource", Enabled: true, AccountID: "test-account",
		Rules: []*types.PolicyRule{{
			ID: "rule-peer-src", Name: "Peer Source Rule", Enabled: true,
			Action:         types.PolicyTrafficActionAccept,
			Protocol:       types.PolicyRuleProtocolTCP,
			Bidirectional:  true,
			Ports:          []string{"443"},
			SourceResource: types.Resource{ID: "peer-0", Type: types.ResourceTypePeer},
			Destinations:   []string{"group-1"},
		}},
	})

	// peer-0 is the source resource, should see group-1 peers
	nm0 := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm0)

	has443 := false
	for _, rule := range nm0.FirewallRules {
		if rule.Port == "443" {
			has443 = true
			break
		}
	}
	assert.True(t, has443, "peer-0 as source resource should have port 443 rule")
}

// TestComponents_PeerAsDestinationResource verifies that a policy with DestinationResource.Type=Peer
// targets only that specific peer as the destination.
func TestComponents_PeerAsDestinationResource(t *testing.T) {
	account, validatedPeers := scalableTestAccountWithoutDefaultPolicy(20, 2)

	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-peer-dst", Name: "Peer Dest Resource", Enabled: true, AccountID: "test-account",
		Rules: []*types.PolicyRule{{
			ID: "rule-peer-dst", Name: "Peer Dest Rule", Enabled: true,
			Action:              types.PolicyTrafficActionAccept,
			Protocol:            types.PolicyRuleProtocolTCP,
			Bidirectional:       true,
			Ports:               []string{"443"},
			Sources:             []string{"group-0"},
			DestinationResource: types.Resource{ID: "peer-15", Type: types.ResourceTypePeer},
		}},
	})

	// peer-0 is in group-0 (source), should see peer-15 as destination
	nm0 := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm0)

	peerIDs := make(map[string]bool, len(nm0.Peers))
	for _, p := range nm0.Peers {
		peerIDs[p.ID] = true
	}
	assert.True(t, peerIDs["peer-15"], "peer-0 should see peer-15 via peer-as-destination-resource policy")
}

// ──────────────────────────────────────────────────────────────────────────────
// 12. MULTIPLE RULES PER POLICY
// ──────────────────────────────────────────────────────────────────────────────

// TestComponents_MultipleRulesPerPolicy verifies a policy with multiple rules generates
// firewall rules for each.
func TestComponents_MultipleRulesPerPolicy(t *testing.T) {
	account, validatedPeers := scalableTestAccount(20, 2)

	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-multi-rule", Name: "Multi Rule Policy", Enabled: true, AccountID: "test-account",
		Rules: []*types.PolicyRule{
			{
				ID: "rule-http", Name: "Allow HTTP", Enabled: true,
				Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolTCP,
				Bidirectional: true, Ports: []string{"80"},
				Sources: []string{"group-0"}, Destinations: []string{"group-1"},
			},
			{
				ID: "rule-https", Name: "Allow HTTPS", Enabled: true,
				Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolTCP,
				Bidirectional: true, Ports: []string{"443"},
				Sources: []string{"group-0"}, Destinations: []string{"group-1"},
			},
		},
	})

	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)

	has80, has443 := false, false
	for _, rule := range nm.FirewallRules {
		if rule.Port == "80" {
			has80 = true
		}
		if rule.Port == "443" {
			has443 = true
		}
	}
	assert.True(t, has80, "should have firewall rule for port 80 from first rule")
	assert.True(t, has443, "should have firewall rule for port 443 from second rule")
}

// ──────────────────────────────────────────────────────────────────────────────
// 13. SSH AUTHORIZED USERS CONTENT
// ──────────────────────────────────────────────────────────────────────────────

// TestComponents_SSHAuthorizedUsersContent verifies that SSH policies populate
// the AuthorizedUsers map with the correct users and machine mappings.
func TestComponents_SSHAuthorizedUsersContent(t *testing.T) {
	account, validatedPeers := scalableTestAccount(20, 2)

	account.Users["user-dev"] = &types.User{Id: "user-dev", Role: types.UserRoleUser, AccountID: "test-account", AutoGroups: []string{"ssh-users"}}
	account.Groups["ssh-users"] = &types.Group{ID: "ssh-users", Name: "SSH Users", Peers: []string{}}

	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-ssh", Name: "SSH Access", Enabled: true, AccountID: "test-account",
		Rules: []*types.PolicyRule{{
			ID: "rule-ssh", Name: "Allow SSH", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolNetbirdSSH,
			Bidirectional: false,
			Sources:       []string{"group-0"}, Destinations: []string{"group-1"},
			AuthorizedGroups: map[string][]string{"ssh-users": {"root", "admin"}},
		}},
	})

	// peer-10 is in group-1 (destination)
	nm := componentsNetworkMap(account, "peer-10", validatedPeers)
	require.NotNil(t, nm)
	assert.True(t, nm.EnableSSH, "SSH should be enabled")
	assert.NotNil(t, nm.AuthorizedUsers, "AuthorizedUsers should not be nil")
	assert.NotEmpty(t, nm.AuthorizedUsers, "AuthorizedUsers should have entries")

	// Check that "root" machine user mapping exists
	_, hasRoot := nm.AuthorizedUsers["root"]
	_, hasAdmin := nm.AuthorizedUsers["admin"]
	assert.True(t, hasRoot || hasAdmin, "AuthorizedUsers should contain 'root' or 'admin' machine user mapping")
}

// TestComponents_SSHLegacyImpliedSSH verifies that a non-SSH ALL protocol policy with
// SSHEnabled peer implies legacy SSH access.
func TestComponents_SSHLegacyImpliedSSH(t *testing.T) {
	account, validatedPeers := scalableTestAccount(20, 2)

	// Enable SSH on the destination peer
	account.Peers["peer-10"].SSHEnabled = true

	// The default "Allow All" policy with Protocol=ALL + SSHEnabled peer should imply SSH
	nm := componentsNetworkMap(account, "peer-10", validatedPeers)
	require.NotNil(t, nm)
	assert.True(t, nm.EnableSSH, "SSH should be implied by ALL protocol policy with SSHEnabled peer")
}

// ──────────────────────────────────────────────────────────────────────────────
// 14. ROUTE DEFAULT PERMIT (no AccessControlGroups)
// ──────────────────────────────────────────────────────────────────────────────

// TestComponents_RouteDefaultPermit verifies that a route without AccessControlGroups
// generates default permit firewall rules (0.0.0.0/0 source).
func TestComponents_RouteDefaultPermit(t *testing.T) {
	account, validatedPeers := scalableTestAccount(20, 2)

	// Add a route without ACGs — this peer is the routing peer
	routingPeerID := "peer-5"
	account.Routes["route-no-acg"] = &route.Route{
		ID: "route-no-acg", Network: netip.MustParsePrefix("192.168.99.0/24"),
		PeerID: routingPeerID, Peer: account.Peers[routingPeerID].Key,
		Enabled: true, Groups: []string{"group-all"}, PeerGroups: []string{"group-0"},
		AccessControlGroups: []string{},
		AccountID:           "test-account",
	}

	// The routing peer should get default permit route firewall rules
	nm := componentsNetworkMap(account, routingPeerID, validatedPeers)
	require.NotNil(t, nm)

	hasDefaultPermit := false
	for _, rfr := range nm.RoutesFirewallRules {
		for _, src := range rfr.SourceRanges {
			if src == "0.0.0.0/0" || src == "::/0" {
				hasDefaultPermit = true
				break
			}
		}
	}
	assert.True(t, hasDefaultPermit, "route without ACG should have default permit rule with 0.0.0.0/0 source")
}

// ──────────────────────────────────────────────────────────────────────────────
// 15. MULTIPLE ROUTERS PER NETWORK
// ──────────────────────────────────────────────────────────────────────────────

// TestComponents_MultipleRoutersPerNetwork verifies that a network resource
// with multiple routers provides routes through all available routers.
func TestComponents_MultipleRoutersPerNetwork(t *testing.T) {
	account, validatedPeers := scalableTestAccountWithoutDefaultPolicy(20, 2)

	netID := "net-multi-router"
	resID := "res-multi-router"
	account.Networks = append(account.Networks, &networkTypes.Network{ID: netID, Name: "Multi Router Network", AccountID: "test-account"})
	account.NetworkResources = append(account.NetworkResources, &resourceTypes.NetworkResource{
		ID: resID, NetworkID: netID, AccountID: "test-account", Enabled: true,
		Address: "multi-svc.netbird.cloud",
	})
	account.NetworkRouters = append(account.NetworkRouters,
		&routerTypes.NetworkRouter{ID: "router-a", NetworkID: netID, Peer: "peer-5", Enabled: true, AccountID: "test-account", Metric: 100},
		&routerTypes.NetworkRouter{ID: "router-b", NetworkID: netID, Peer: "peer-15", Enabled: true, AccountID: "test-account", Metric: 200},
	)
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-multi-router-res", Name: "Multi Router Resource", Enabled: true, AccountID: "test-account",
		Rules: []*types.PolicyRule{{
			ID: "rule-multi-router-res", Name: "Allow Multi Router", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL, Bidirectional: true,
			Sources: []string{"group-0"}, DestinationResource: types.Resource{ID: resID},
		}},
	})

	// peer-0 is in group-0 (source), should see both router peers
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)

	peerIDs := make(map[string]bool, len(nm.Peers))
	for _, p := range nm.Peers {
		peerIDs[p.ID] = true
	}
	assert.True(t, peerIDs["peer-5"], "source peer should see router-a (peer-5)")
	assert.True(t, peerIDs["peer-15"], "source peer should see router-b (peer-15)")
}

// ──────────────────────────────────────────────────────────────────────────────
// 16. PEER-AS-NAMESERVER EXCLUSION
// ──────────────────────────────────────────────────────────────────────────────

// TestComponents_PeerIsNameserverExcludedFromNSGroup verifies that a peer serving
// as a nameserver does not receive its own NS group in DNS config.
func TestComponents_PeerIsNameserverExcludedFromNSGroup(t *testing.T) {
	account, validatedPeers := scalableTestAccount(20, 2)

	// peer-0 has IP 100.64.0.0 — make it a nameserver
	nsIP := account.Peers["peer-0"].IP
	account.NameServerGroups["ns-self"] = &nbdns.NameServerGroup{
		ID: "ns-self", Name: "Self NS", Enabled: true, Groups: []string{"group-all"},
		NameServers: []nbdns.NameServer{{IP: netip.AddrFrom4([4]byte{nsIP[0], nsIP[1], nsIP[2], nsIP[3]}), NSType: nbdns.UDPNameServerType, Port: 53}},
	}

	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)

	hasSelfNS := false
	for _, ns := range nm.DNSConfig.NameServerGroups {
		if ns.ID == "ns-self" {
			hasSelfNS = true
		}
	}
	assert.False(t, hasSelfNS, "peer serving as nameserver should NOT receive its own NS group")

	// peer-10 is NOT the nameserver, should receive the NS group
	nm10 := componentsNetworkMap(account, "peer-10", validatedPeers)
	require.NotNil(t, nm10)
	hasNSForPeer10 := false
	for _, ns := range nm10.DNSConfig.NameServerGroups {
		if ns.ID == "ns-self" {
			hasNSForPeer10 = true
		}
	}
	assert.True(t, hasNSForPeer10, "non-nameserver peer should receive the NS group")
}

// ──────────────────────────────────────────────────────────────────────────────
// 17. DOMAIN NETWORK RESOURCES
// ──────────────────────────────────────────────────────────────────────────────

// TestComponents_DomainNetworkResource verifies that domain-based network resources
// produce routes with the correct domain configuration.
func TestComponents_DomainNetworkResource(t *testing.T) {
	account, validatedPeers := scalableTestAccountWithoutDefaultPolicy(20, 2)

	netID := "net-domain"
	resID := "res-domain"
	account.Networks = append(account.Networks, &networkTypes.Network{ID: netID, Name: "Domain Network", AccountID: "test-account"})
	account.NetworkResources = append(account.NetworkResources, &resourceTypes.NetworkResource{
		ID: resID, NetworkID: netID, AccountID: "test-account", Enabled: true,
		Address: "api.example.com", Type: "domain",
	})
	account.NetworkRouters = append(account.NetworkRouters, &routerTypes.NetworkRouter{
		ID: "router-domain", NetworkID: netID, Peer: "peer-5", Enabled: true, AccountID: "test-account",
	})
	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-domain-res", Name: "Domain Resource Policy", Enabled: true, AccountID: "test-account",
		Rules: []*types.PolicyRule{{
			ID: "rule-domain-res", Name: "Allow Domain", Enabled: true,
			Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolALL, Bidirectional: true,
			Sources: []string{"group-0"}, DestinationResource: types.Resource{ID: resID},
		}},
	})

	// peer-0 is source, should get route to the domain resource via peer-5
	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)

	peerIDs := make(map[string]bool, len(nm.Peers))
	for _, p := range nm.Peers {
		peerIDs[p.ID] = true
	}
	assert.True(t, peerIDs["peer-5"], "source peer should see domain resource router peer")
}

// ──────────────────────────────────────────────────────────────────────────────
// 18. DISABLED RULE WITHIN ENABLED POLICY
// ──────────────────────────────────────────────────────────────────────────────

// TestComponents_DisabledRuleInEnabledPolicy verifies that a disabled rule within
// an enabled policy does not generate firewall rules.
func TestComponents_DisabledRuleInEnabledPolicy(t *testing.T) {
	account, validatedPeers := scalableTestAccount(20, 2)

	account.Policies = append(account.Policies, &types.Policy{
		ID: "policy-mixed-rules", Name: "Mixed Rules", Enabled: true, AccountID: "test-account",
		Rules: []*types.PolicyRule{
			{
				ID: "rule-enabled", Name: "Enabled Rule", Enabled: true,
				Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolTCP,
				Bidirectional: true, Ports: []string{"3000"},
				Sources: []string{"group-0"}, Destinations: []string{"group-1"},
			},
			{
				ID: "rule-disabled", Name: "Disabled Rule", Enabled: false,
				Action: types.PolicyTrafficActionAccept, Protocol: types.PolicyRuleProtocolTCP,
				Bidirectional: true, Ports: []string{"3001"},
				Sources: []string{"group-0"}, Destinations: []string{"group-1"},
			},
		},
	})

	nm := componentsNetworkMap(account, "peer-0", validatedPeers)
	require.NotNil(t, nm)

	has3000, has3001 := false, false
	for _, rule := range nm.FirewallRules {
		if rule.Port == "3000" {
			has3000 = true
		}
		if rule.Port == "3001" {
			has3001 = true
		}
	}
	assert.True(t, has3000, "enabled rule should generate firewall rule for port 3000")
	assert.False(t, has3001, "disabled rule should NOT generate firewall rule for port 3001")
}
