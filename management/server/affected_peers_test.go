package server

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	nbdns "github.com/netbirdio/netbird/dns"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

// setupAffectedPeersTest creates a manager with a clean account and 5 peers, each in its own group.
// Returns the manager, store, account ID, peer IDs, and group IDs.
// Peer layout:
//
//	peer0 -> group0
//	peer1 -> group1
//	peer2 -> group2
//	peer3 -> group3
//	peer4 -> group4
func setupAffectedPeersTest(t *testing.T) (*DefaultAccountManager, store.Store, string, []string, []string) {
	t.Helper()

	manager, _, err := createManager(t)
	require.NoError(t, err)

	account, err := createAccount(manager, "affected_test", userID, "")
	require.NoError(t, err)

	ctx := context.Background()
	accountID := account.Id

	// Delete the default "All <-> All" policy so tests start with a clean slate
	policies, err := manager.Store.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)
	for _, p := range policies {
		err := manager.Store.DeletePolicy(ctx, accountID, p.ID)
		require.NoError(t, err)
	}

	setupKey, err := manager.CreateSetupKey(ctx, accountID, "test-key", types.SetupKeyReusable, time.Hour, nil, 999, userID, false, false)
	require.NoError(t, err)

	peerIDs := make([]string, 5)
	for i := 0; i < 5; i++ {
		peer := addPeerToAccount(t, manager, accountID, setupKey.Key)
		peerIDs[i] = peer.ID
	}

	groupIDs := make([]string, 5)
	for i := 0; i < 5; i++ {
		g := &types.Group{
			ID:    affectedGroupID(i),
			Name:  affectedGroupName(i),
			Peers: []string{peerIDs[i]},
		}
		err := manager.CreateGroup(ctx, accountID, userID, g)
		require.NoError(t, err)
		groupIDs[i] = g.ID
	}

	return manager, manager.Store, accountID, peerIDs, groupIDs
}

func affectedGroupID(i int) string   { return fmt.Sprintf("affected-grp-%d", i) }
func affectedGroupName(i int) string { return fmt.Sprintf("AffectedGroup%d", i) }

// ---------- collectGroupChangeAffectedGroups ----------

func TestCollectGroupChange_NoEntities(t *testing.T) {
	_, s, accountID, _, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// group0 is not referenced by any entity
	groups, directPeers := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Empty(t, groups, "no entities reference group0, should return no affected groups")
	assert.Empty(t, directPeers, "no entities reference group0, should return no direct peers")
}

func TestCollectGroupChange_EmptyInput(t *testing.T) {
	_, s, accountID, _, _ := setupAffectedPeersTest(t)
	ctx := context.Background()

	groups, directPeers := collectGroupChangeAffectedGroups(ctx, s, accountID, nil)
	assert.Nil(t, groups)
	assert.Nil(t, directPeers)

	groups, directPeers = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{})
	assert.Nil(t, groups)
	assert.Nil(t, directPeers)
}

func TestCollectGroupChange_PolicyLinked(t *testing.T) {
	manager, s, accountID, _, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Create policy: group0 (src) <-> group1 (dst)
	_, err := manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{groupIDs[0]},
				Destinations:  []string{groupIDs[1]},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	// Changing group0 should include both group0 and group1 (from the policy rule)
	groups, _ := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Contains(t, groups, groupIDs[0])
	assert.Contains(t, groups, groupIDs[1])

	// Changing group1 should also include both groups
	groups, _ = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[1]})
	assert.Contains(t, groups, groupIDs[0])
	assert.Contains(t, groups, groupIDs[1])

	// Changing group2 (not in policy) should return nothing
	groups, _ = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[2]})
	assert.Empty(t, groups)
}

func TestCollectGroupChange_PolicyWithDirectPeerResource(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Create policy with direct peer resource
	_, err := manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:        true,
				Sources:        []string{groupIDs[0]},
				SourceResource: types.Resource{ID: peerIDs[3], Type: types.ResourceTypePeer},
				Destinations:   []string{groupIDs[1]},
				Action:         types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	groups, directPeers := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Contains(t, groups, groupIDs[0])
	assert.Contains(t, groups, groupIDs[1])
	assert.Contains(t, directPeers, peerIDs[3], "direct peer resource should be in directPeers")
}

func TestCollectGroupChange_RouteLinked(t *testing.T) {
	manager, s, accountID, _, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Create route: PeerGroups=[group0], Groups(distribution)=[group1]
	_, err := manager.CreateRoute(ctx, accountID,
		netip.MustParsePrefix("10.0.0.0/24"), // network
		route.IPv4Network,                    // type
		nil,                                  // domains
		"",                                   // peer
		[]string{groupIDs[0]},                // peerGroups
		"test route",                         // description
		"testnet",                            // netID
		false,                                // masquerade
		9999,                                 // metric
		[]string{groupIDs[1]},                // groups (distribution)
		[]string{groupIDs[2]},                // accessControlGroups
		true,                                 // enabled
		userID,
		false, // keepRoute
		false, // skipAutoApply
	)
	require.NoError(t, err)

	// Changing group0 (peerGroups) should include group0, group1, group2
	groups, _ := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Contains(t, groups, groupIDs[0])
	assert.Contains(t, groups, groupIDs[1])
	assert.Contains(t, groups, groupIDs[2])

	// Changing group1 (distribution) should include all three
	groups, _ = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[1]})
	assert.Contains(t, groups, groupIDs[0])
	assert.Contains(t, groups, groupIDs[1])
	assert.Contains(t, groups, groupIDs[2])

	// Changing group3 (not in route) should return nothing
	groups, _ = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[3]})
	assert.Empty(t, groups)
}

func TestCollectGroupChange_RouteWithDirectPeer(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Create route with direct peer
	_, err := manager.CreateRoute(ctx, accountID,
		netip.MustParsePrefix("10.1.0.0/24"),
		route.IPv4Network,
		nil,
		peerIDs[4], // direct peer
		nil,        // no peerGroups
		"test route peer",
		"testnet2",
		false,
		9999,
		[]string{groupIDs[1]}, // distribution groups
		nil,
		true,
		userID,
		false,
		false,
	)
	require.NoError(t, err)

	// Changing group1 should include group1 and direct peer4
	groups, directPeers := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[1]})
	assert.Contains(t, groups, groupIDs[1])
	assert.Contains(t, directPeers, peerIDs[4])
}

func TestCollectGroupChange_NameServerGroupLinked(t *testing.T) {
	manager, s, accountID, _, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Create nameserver group with group0
	_, err := manager.CreateNameServerGroup(ctx, accountID, "ns1", "NS Group 1",
		[]nbdns.NameServer{{
			IP:     netip.MustParseAddr("1.1.1.1"),
			NSType: nbdns.UDPNameServerType,
			Port:   nbdns.DefaultDNSPort,
		}},
		[]string{groupIDs[0]},
		true, nil, true, userID, false,
	)
	require.NoError(t, err)

	// Changing group0 should include group0 (the NS group references it)
	groups, _ := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Contains(t, groups, groupIDs[0])

	// Changing group1 (not in NS group) should not include anything from NS
	groups, _ = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[1]})
	assert.Empty(t, groups)
}

func TestCollectGroupChange_DNSSettingsLinked(t *testing.T) {
	manager, s, accountID, _, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	err := manager.SaveDNSSettings(ctx, accountID, userID, &types.DNSSettings{
		DisabledManagementGroups: []string{groupIDs[2]},
	})
	require.NoError(t, err)

	// Changing group2 should include group2 (from DNS disabled management)
	groups, _ := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[2]})
	assert.Contains(t, groups, groupIDs[2])

	// Changing group0 (not in DNS settings) should return nothing
	groups, _ = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Empty(t, groups)
}

func TestCollectGroupChange_NetworkRouterLinked(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Create network and router
	net1 := &networkTypes.Network{
		ID:        "net-test-1",
		AccountID: accountID,
		Name:      "test-network",
	}
	err := manager.Store.SaveNetwork(ctx, net1)
	require.NoError(t, err)

	err = manager.Store.SaveNetworkRouter(ctx, &routerTypes.NetworkRouter{
		ID:         "router1",
		NetworkID:  net1.ID,
		AccountID:  accountID,
		PeerGroups: []string{groupIDs[0]},
		Peer:       peerIDs[3],
	})
	require.NoError(t, err)

	// Changing group0 should include group0 and direct peer3
	groups, directPeers := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Contains(t, groups, groupIDs[0])
	assert.Contains(t, directPeers, peerIDs[3])

	// Changing group1 (not in router) should return nothing
	groups, directPeers = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[1]})
	assert.Empty(t, groups)
	assert.Empty(t, directPeers)
}

func TestCollectGroupChange_MultipleEntities(t *testing.T) {
	manager, s, accountID, _, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Policy: group0 <-> group1
	_, err := manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{groupIDs[0]},
				Destinations:  []string{groupIDs[1]},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	// Route: PeerGroups=[group2], distribution=[group3]
	_, err = manager.CreateRoute(ctx, accountID,
		netip.MustParsePrefix("10.2.0.0/24"),
		route.IPv4Network,
		nil,
		"",
		[]string{groupIDs[2]},
		"multi route",
		"multinet",
		false,
		9999,
		[]string{groupIDs[3]},
		nil,
		true,
		userID,
		false,
		false,
	)
	require.NoError(t, err)

	// Changing group0 should only pick up policy groups (group0, group1), not route groups
	groups, directPeers := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Contains(t, groups, groupIDs[0])
	assert.Contains(t, groups, groupIDs[1])
	assert.NotContains(t, groups, groupIDs[2], "route groups should not be included for group0 change")
	assert.NotContains(t, groups, groupIDs[3], "route groups should not be included for group0 change")
	assert.Empty(t, directPeers)

	// Changing group3 should only pick up route groups (group2, group3)
	groups, directPeers = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[3]})
	assert.Contains(t, groups, groupIDs[2])
	assert.Contains(t, groups, groupIDs[3])
	assert.NotContains(t, groups, groupIDs[0], "policy groups should not be included for group3 change")
	assert.NotContains(t, groups, groupIDs[1], "policy groups should not be included for group3 change")
	assert.Empty(t, directPeers)
}

// ---------- collectPolicyAffectedGroupsAndPeers ----------

func TestCollectPolicyAffectedGroups_Basic(t *testing.T) {
	policy := &types.Policy{
		Rules: []*types.PolicyRule{
			{
				Sources:      []string{"g1", "g2"},
				Destinations: []string{"g3"},
			},
		},
	}
	groups, directPeers := collectPolicyAffectedGroupsAndPeers(policy)
	assert.ElementsMatch(t, []string{"g1", "g2", "g3"}, groups)
	assert.Empty(t, directPeers)
}

func TestCollectPolicyAffectedGroups_WithPeerResources(t *testing.T) {
	policy := &types.Policy{
		Rules: []*types.PolicyRule{
			{
				Sources:             []string{"g1"},
				SourceResource:      types.Resource{ID: "p1", Type: types.ResourceTypePeer},
				Destinations:        []string{"g2"},
				DestinationResource: types.Resource{ID: "p2", Type: types.ResourceTypePeer},
			},
		},
	}
	groups, directPeers := collectPolicyAffectedGroupsAndPeers(policy)
	assert.ElementsMatch(t, []string{"g1", "g2"}, groups)
	assert.ElementsMatch(t, []string{"p1", "p2"}, directPeers)
}

func TestCollectPolicyAffectedGroups_NilPolicy(t *testing.T) {
	groups, directPeers := collectPolicyAffectedGroupsAndPeers(nil)
	assert.Nil(t, groups)
	assert.Nil(t, directPeers)
}

func TestCollectPolicyAffectedGroups_MultipleRules(t *testing.T) {
	policy := &types.Policy{
		Rules: []*types.PolicyRule{
			{Sources: []string{"g1"}, Destinations: []string{"g2"}},
			{Sources: []string{"g3"}, Destinations: []string{"g4"}},
		},
	}
	groups, _ := collectPolicyAffectedGroupsAndPeers(policy)
	assert.ElementsMatch(t, []string{"g1", "g2", "g3", "g4"}, groups)
}

// ---------- collectRouteAffectedGroupsAndPeers ----------

func TestCollectRouteAffectedGroups_Basic(t *testing.T) {
	r := &route.Route{
		Groups:              []string{"g1"},
		PeerGroups:          []string{"g2"},
		AccessControlGroups: []string{"g3"},
	}
	groups, directPeers := collectRouteAffectedGroupsAndPeers(r)
	assert.ElementsMatch(t, []string{"g1", "g2", "g3"}, groups)
	assert.Empty(t, directPeers)
}

func TestCollectRouteAffectedGroups_WithDirectPeer(t *testing.T) {
	r := &route.Route{
		Groups: []string{"g1"},
		Peer:   "p1",
	}
	groups, directPeers := collectRouteAffectedGroupsAndPeers(r)
	assert.ElementsMatch(t, []string{"g1"}, groups)
	assert.ElementsMatch(t, []string{"p1"}, directPeers)
}

func TestCollectRouteAffectedGroups_NilRoute(t *testing.T) {
	groups, directPeers := collectRouteAffectedGroupsAndPeers(nil)
	assert.Nil(t, groups)
	assert.Nil(t, directPeers)
}

// ---------- resolvePeerIDs ----------

func TestResolvePeerIDs_GroupsOnly(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// group0 has peer0, group1 has peer1
	result := manager.resolvePeerIDs(ctx, s, accountID, []string{groupIDs[0], groupIDs[1]}, nil)
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1]}, result)
}

func TestResolvePeerIDs_WithDirectPeers(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// group0 has peer0, plus direct peer2
	result := manager.resolvePeerIDs(ctx, s, accountID, []string{groupIDs[0]}, []string{peerIDs[2]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[2]}, result)
}

func TestResolvePeerIDs_Deduplication(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// peer0 is in group0 and also passed as direct peer -> should appear once
	result := manager.resolvePeerIDs(ctx, s, accountID, []string{groupIDs[0]}, []string{peerIDs[0]})
	assert.Len(t, result, 1)
	assert.Equal(t, peerIDs[0], result[0])
}

func TestResolvePeerIDs_EmptyInputs(t *testing.T) {
	manager, s, accountID, _, _ := setupAffectedPeersTest(t)
	ctx := context.Background()

	result := manager.resolvePeerIDs(ctx, s, accountID, nil, nil)
	assert.Empty(t, result)
}

// ---------- resolveAffectedPeersForPeerChanges (end-to-end) ----------

func TestResolveAffectedPeers_NoPoliciesOrRoutes(t *testing.T) {
	manager, s, accountID, peerIDs, _ := setupAffectedPeersTest(t)
	ctx := context.Background()

	// No entity references any group, so changing peer0 should yield 0 affected peers
	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.Empty(t, result, "no entities reference any group, should return no affected peers")
}

func TestResolveAffectedPeers_PolicyBetweenTwoGroups(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Policy: group0 (src) <-> group1 (dst)
	_, err := manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{groupIDs[0]},
				Destinations:  []string{groupIDs[1]},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	// Changing peer0 (in group0) should affect peer0 + peer1
	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1]}, result)

	// Changing peer1 (in group1) should also affect peer0 + peer1
	result = manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[1]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1]}, result)

	// Changing peer2 (in group2, not in policy) should return empty
	result = manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[2]})
	assert.Empty(t, result)
}

func TestResolveAffectedPeers_PolicyThreeGroups(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Policy with multiple sources/destinations: group0,group1 -> group2
	_, err := manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:      true,
				Sources:      []string{groupIDs[0], groupIDs[1]},
				Destinations: []string{groupIDs[2]},
				Action:       types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	// Changing peer0 (in group0) should affect peer0 + peer1 + peer2
	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1], peerIDs[2]}, result)
}

func TestResolveAffectedPeers_RoutePeerGroups(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Route: peerGroups=[group0], distribution=[group1]
	_, err := manager.CreateRoute(ctx, accountID,
		netip.MustParsePrefix("10.3.0.0/24"),
		route.IPv4Network,
		nil,
		"",
		[]string{groupIDs[0]},
		"test route",
		"routenet",
		false,
		9999,
		[]string{groupIDs[1]},
		nil,
		true,
		userID,
		false,
		false,
	)
	require.NoError(t, err)

	// Changing peer0 (in group0/peerGroups) should affect peer0 + peer1
	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1]}, result)

	// Changing peer1 (in group1/distribution) should also affect peer0 + peer1
	result = manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[1]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1]}, result)

	// Changing peer2 (unrelated) should return empty
	result = manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[2]})
	assert.Empty(t, result)
}

func TestResolveAffectedPeers_RouteWithDirectPeer(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Route with direct peer: peer=peer4, distribution=[group1]
	_, err := manager.CreateRoute(ctx, accountID,
		netip.MustParsePrefix("10.4.0.0/24"),
		route.IPv4Network,
		nil,
		peerIDs[4],
		nil,
		"route with peer",
		"routenet2",
		false,
		9999,
		[]string{groupIDs[1]},
		nil,
		true,
		userID,
		false,
		false,
	)
	require.NoError(t, err)

	// Changing peer1 (in distribution group1) should affect peer1 + direct peer4
	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[1]})
	assert.ElementsMatch(t, []string{peerIDs[1], peerIDs[4]}, result)
}

func TestResolveAffectedPeers_NetworkRouter(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Create network + router with peerGroups=[group0], direct peer=peer3
	net1 := &networkTypes.Network{
		ID:        "net-test-2",
		AccountID: accountID,
		Name:      "test-net",
	}
	err := manager.Store.SaveNetwork(ctx, net1)
	require.NoError(t, err)

	err = manager.Store.SaveNetworkRouter(ctx, &routerTypes.NetworkRouter{
		ID:         "router-test",
		NetworkID:  net1.ID,
		AccountID:  accountID,
		PeerGroups: []string{groupIDs[0]},
		Peer:       peerIDs[3],
	})
	require.NoError(t, err)

	// Changing peer0 (in group0) should affect peer0 + peer3 (direct)
	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[3]}, result)
}

func TestResolveAffectedPeers_NameServerGroup(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// NS group with group0
	_, err := manager.CreateNameServerGroup(ctx, accountID, "ns-test", "NS Test",
		[]nbdns.NameServer{{
			IP:     netip.MustParseAddr("8.8.8.8"),
			NSType: nbdns.UDPNameServerType,
			Port:   nbdns.DefaultDNSPort,
		}},
		[]string{groupIDs[0]},
		true, nil, true, userID, false,
	)
	require.NoError(t, err)

	// Changing peer0 (in group0) should affect peer0
	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.Contains(t, result, peerIDs[0])
}

func TestResolveAffectedPeers_DNSSettings(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// DNS disabled management on group0
	err := manager.SaveDNSSettings(ctx, accountID, userID, &types.DNSSettings{
		DisabledManagementGroups: []string{groupIDs[0]},
	})
	require.NoError(t, err)

	// Changing peer0 (in group0) should affect peer0
	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.Contains(t, result, peerIDs[0])
}

func TestResolveAffectedPeers_PeerInMultipleGroups(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Add peer0 to group1 as well
	err := manager.GroupAddPeer(ctx, accountID, groupIDs[1], peerIDs[0])
	require.NoError(t, err)

	// Policy: group0 -> group2
	_, err = manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:      true,
				Sources:      []string{groupIDs[0]},
				Destinations: []string{groupIDs[2]},
				Action:       types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	// Another policy: group1 -> group3
	_, err = manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:      true,
				Sources:      []string{groupIDs[1]},
				Destinations: []string{groupIDs[3]},
				Action:       types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	// Changing peer0 (in group0 AND group1) should affect:
	// From policy1: group0+group2 -> peer0, peer2
	// From policy2: group1+group3 -> peer0, peer1, peer3
	// Total: peer0, peer1, peer2, peer3
	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1], peerIDs[2], peerIDs[3]}, result)
}

func TestResolveAffectedPeers_MultipleChangedPeers(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Policy: group0 <-> group1
	_, err := manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{groupIDs[0]},
				Destinations:  []string{groupIDs[1]},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	// Another policy: group2 <-> group3
	_, err = manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{groupIDs[2]},
				Destinations:  []string{groupIDs[3]},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	// Changing peer0 AND peer2 at once
	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0], peerIDs[2]})
	// peer0 -> policy1 -> peer0, peer1
	// peer2 -> policy2 -> peer2, peer3
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1], peerIDs[2], peerIDs[3]}, result)
}

func TestResolveAffectedPeers_SharedGroupAcrossPolicyAndRoute(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Policy: group0 <-> group1
	_, err := manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{groupIDs[0]},
				Destinations:  []string{groupIDs[1]},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	// Route: distribution=[group0], peerGroups=[group2]
	_, err = manager.CreateRoute(ctx, accountID,
		netip.MustParsePrefix("10.5.0.0/24"),
		route.IPv4Network,
		nil,
		"",
		[]string{groupIDs[2]},
		"shared group route",
		"sharednet",
		false,
		9999,
		[]string{groupIDs[0]},
		nil,
		true,
		userID,
		false,
		false,
	)
	require.NoError(t, err)

	// Changing peer0 (in group0) should affect:
	// From policy: group0+group1 -> peer0, peer1
	// From route: group0+group2 -> peer0, peer2
	// Total: peer0, peer1, peer2
	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1], peerIDs[2]}, result)
}

func TestResolveAffectedPeers_EmptyChangedPeers(t *testing.T) {
	manager, s, accountID, _, _ := setupAffectedPeersTest(t)
	ctx := context.Background()

	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, nil)
	assert.Empty(t, result)

	result = manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{})
	assert.Empty(t, result)
}

// ---------- Integration: peer changes with full update flow ----------

func TestAffectedPeers_GroupUpdateOnlyAffectsLinkedPeers(t *testing.T) {
	manager, updateManager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)
	ctx := context.Background()
	accountID := account.Id

	// Delete the default "All <-> All" policy so only our explicit policy matters
	policies, err := manager.Store.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)
	for _, p := range policies {
		err := manager.Store.DeletePolicy(ctx, accountID, p.ID)
		require.NoError(t, err)
	}

	// Create groups
	for _, g := range []*types.Group{
		{ID: "ap-grpA", Name: "AP-A", Peers: []string{peer1.ID}},
		{ID: "ap-grpB", Name: "AP-B", Peers: []string{peer2.ID}},
		{ID: "ap-grpC", Name: "AP-C", Peers: []string{peer3.ID}},
	} {
		err := manager.CreateGroup(ctx, accountID, userID, g)
		require.NoError(t, err)
	}

	// Policy: grpA <-> grpB (peer1 <-> peer2). peer3 is NOT in this policy.
	_, err = manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{"ap-grpA"},
				Destinations:  []string{"ap-grpB"},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	// Open update channels for all peers
	updMsg1 := updateManager.CreateChannel(ctx, peer1.ID)
	updMsg2 := updateManager.CreateChannel(ctx, peer2.ID)
	updMsg3 := updateManager.CreateChannel(ctx, peer3.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(ctx, peer1.ID)
		updateManager.CloseChannel(ctx, peer2.ID)
		updateManager.CloseChannel(ctx, peer3.ID)
	})

	// Verify resolution: changing peer1 should only affect peer1 and peer2
	result := manager.resolveAffectedPeersForPeerChanges(ctx, manager.Store, accountID, []string{peer1.ID})
	assert.ElementsMatch(t, []string{peer1.ID, peer2.ID}, result)

	// Updating grpA to include peer3 should update all 3 peers because after the update
	// grpA={peer1,peer3} which is in the policy, plus grpB={peer2}
	t.Run("group change updates all peers in policy groups", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg1)
			peerShouldReceiveUpdate(t, updMsg2)
			peerShouldReceiveUpdate(t, updMsg3) // peer3 is now in grpA which is in the policy
			close(done)
		}()

		err := manager.UpdateGroup(ctx, accountID, userID, &types.Group{
			ID:    "ap-grpA",
			Name:  "AP-A",
			Peers: []string{peer1.ID, peer3.ID}, // add peer3 to group
		})
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(peerUpdateTimeout):
			t.Error("timeout")
		}
	})

	_ = updMsg1
	_ = updMsg2
	_ = updMsg3
}

func TestAffectedPeers_UnlinkedGroupChange_NoUpdates(t *testing.T) {
	manager, s, accountID, peerIDs, _ := setupAffectedPeersTest(t)
	ctx := context.Background()

	// No entities reference any group
	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.Empty(t, result, "unlinked peer change should produce no affected peers")
}

// ---------- collectPostureCheckAffectedGroupsAndPeers ----------

func TestCollectPostureCheckAffected_NoMatch(t *testing.T) {
	_, s, accountID, _, _ := setupAffectedPeersTest(t)
	ctx := context.Background()

	groups, directPeers := collectPostureCheckAffectedGroupsAndPeers(ctx, s, accountID, "nonexistent-check")
	assert.Empty(t, groups)
	assert.Empty(t, directPeers)
}

// ---------- Isolation: unrelated entities don't bleed ----------

func TestAffectedPeers_IsolatedPolicies(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Policy A: group0 <-> group1
	_, err := manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{groupIDs[0]},
				Destinations:  []string{groupIDs[1]},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	// Policy B: group2 <-> group3
	_, err = manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{groupIDs[2]},
				Destinations:  []string{groupIDs[3]},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	// Changing peer0 should ONLY affect peer0, peer1 (Policy A), NOT peer2, peer3 (Policy B)
	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1]}, result)
	assert.NotContains(t, result, peerIDs[2])
	assert.NotContains(t, result, peerIDs[3])

	// Changing peer2 should ONLY affect peer2, peer3 (Policy B)
	result = manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[2]})
	assert.ElementsMatch(t, []string{peerIDs[2], peerIDs[3]}, result)
	assert.NotContains(t, result, peerIDs[0])
	assert.NotContains(t, result, peerIDs[1])

	// Changing peer4 (not in any policy) should return empty
	result = manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[4]})
	assert.Empty(t, result)
}

func TestAffectedPeers_IsolatedRouteAndPolicy(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Policy: group0 <-> group1
	_, err := manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{groupIDs[0]},
				Destinations:  []string{groupIDs[1]},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	// Route: peerGroups=[group2], distribution=[group3]
	_, err = manager.CreateRoute(ctx, accountID,
		netip.MustParsePrefix("10.6.0.0/24"),
		route.IPv4Network,
		nil,
		"",
		[]string{groupIDs[2]},
		"isolated route",
		"isonet",
		false,
		9999,
		[]string{groupIDs[3]},
		nil,
		true,
		userID,
		false,
		false,
	)
	require.NoError(t, err)

	// Changing peer0 (policy only) -> peer0, peer1
	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1]}, result)
	assert.NotContains(t, result, peerIDs[2])
	assert.NotContains(t, result, peerIDs[3])

	// Changing peer2 (route only) -> peer2, peer3
	result = manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[2]})
	assert.ElementsMatch(t, []string{peerIDs[2], peerIDs[3]}, result)
	assert.NotContains(t, result, peerIDs[0])
	assert.NotContains(t, result, peerIDs[1])
}

// ---------- Helper: verify no duplicates in resolution ----------

func TestResolveAffectedPeers_NoDuplicates(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Add peer0 to multiple groups
	err := manager.GroupAddPeer(ctx, accountID, groupIDs[1], peerIDs[0])
	require.NoError(t, err)
	err = manager.GroupAddPeer(ctx, accountID, groupIDs[2], peerIDs[0])
	require.NoError(t, err)

	// Policy that references all three groups
	_, err = manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:      true,
				Sources:      []string{groupIDs[0], groupIDs[1]},
				Destinations: []string{groupIDs[2]},
				Action:       types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	// peer0 is in group0, group1, group2 - should only appear once
	count := 0
	for _, id := range result {
		if id == peerIDs[0] {
			count++
		}
	}
	assert.Equal(t, 1, count, "peer0 should appear exactly once in results")
}

// ---------- policyReferencesGroups ----------

func TestPolicyReferencesGroups(t *testing.T) {
	policy := &types.Policy{
		Rules: []*types.PolicyRule{
			{
				Sources:      []string{"g1", "g2"},
				Destinations: []string{"g3"},
			},
		},
	}

	tests := []struct {
		name     string
		groupSet map[string]struct{}
		want     bool
	}{
		{"matches source", map[string]struct{}{"g1": {}}, true},
		{"matches destination", map[string]struct{}{"g3": {}}, true},
		{"no match", map[string]struct{}{"g4": {}}, false},
		{"empty set", map[string]struct{}{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := policyReferencesGroups(policy, tt.groupSet)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRouteReferencesGroups(t *testing.T) {
	r := &route.Route{
		Groups:              []string{"g1"},
		PeerGroups:          []string{"g2"},
		AccessControlGroups: []string{"g3"},
	}

	tests := []struct {
		name     string
		groupSet map[string]struct{}
		want     bool
	}{
		{"matches groups", map[string]struct{}{"g1": {}}, true},
		{"matches peerGroups", map[string]struct{}{"g2": {}}, true},
		{"matches accessControl", map[string]struct{}{"g3": {}}, true},
		{"no match", map[string]struct{}{"g4": {}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := routeReferencesGroups(r, tt.groupSet)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRouterReferencesGroups(t *testing.T) {
	router := &routerTypes.NetworkRouter{
		PeerGroups: []string{"g1", "g2"},
	}

	tests := []struct {
		name     string
		groupSet map[string]struct{}
		want     bool
	}{
		{"matches", map[string]struct{}{"g1": {}}, true},
		{"no match", map[string]struct{}{"g3": {}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := routerReferencesGroups(router, tt.groupSet)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------- helpers ----------

func addPeerToAccount(t *testing.T, manager *DefaultAccountManager, accountID, setupKeyKey string) *nbpeer.Peer {
	t.Helper()

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	peer, _, _, err := manager.AddPeer(context.Background(), "", setupKeyKey, "", &nbpeer.Peer{
		Key:  key.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: key.PublicKey().String()},
	}, false)
	require.NoError(t, err)
	return peer
}
