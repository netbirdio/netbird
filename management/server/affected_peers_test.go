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

// setupAffectedPeersTest creates a manager with a clean account (default policy deleted)
// and 5 peers, each in its own group: peer0->group0, peer1->group1, ..., peer4->group4.
func setupAffectedPeersTest(t *testing.T) (*DefaultAccountManager, store.Store, string, []string, []string) {
	t.Helper()

	manager, _, err := createManager(t)
	require.NoError(t, err)

	account, err := createAccount(manager, "affected_test", userID, "")
	require.NoError(t, err)

	ctx := context.Background()
	accountID := account.Id

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

func TestCollectGroupChange_NoEntities(t *testing.T) {
	_, s, accountID, _, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	groups, directPeers := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Empty(t, groups)
	assert.Empty(t, directPeers)
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

	groups, _ := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Contains(t, groups, groupIDs[0])
	assert.Contains(t, groups, groupIDs[1])

	groups, _ = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[1]})
	assert.Contains(t, groups, groupIDs[0])
	assert.Contains(t, groups, groupIDs[1])

	groups, _ = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[2]})
	assert.Empty(t, groups)
}

func TestCollectGroupChange_PolicyWithDirectPeerResource(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

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
	assert.Contains(t, directPeers, peerIDs[3])
}

func TestCollectGroupChange_RouteLinked(t *testing.T) {
	manager, s, accountID, _, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	_, err := manager.CreateRoute(ctx, accountID,
		netip.MustParsePrefix("10.0.0.0/24"),
		route.IPv4Network,
		nil,
		"",
		[]string{groupIDs[0]},
		"test route",
		"testnet",
		false,
		9999,
		[]string{groupIDs[1]},
		[]string{groupIDs[2]},
		true,
		userID,
		false,
		false,
	)
	require.NoError(t, err)

	groups, _ := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Contains(t, groups, groupIDs[0])
	assert.Contains(t, groups, groupIDs[1])
	assert.Contains(t, groups, groupIDs[2])

	groups, _ = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[1]})
	assert.Contains(t, groups, groupIDs[0])
	assert.Contains(t, groups, groupIDs[1])
	assert.Contains(t, groups, groupIDs[2])

	groups, _ = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[3]})
	assert.Empty(t, groups)
}

func TestCollectGroupChange_RouteWithDirectPeer(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	_, err := manager.CreateRoute(ctx, accountID,
		netip.MustParsePrefix("10.1.0.0/24"),
		route.IPv4Network,
		nil,
		peerIDs[4],
		nil,
		"test route peer",
		"testnet2",
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

	groups, directPeers := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[1]})
	assert.Contains(t, groups, groupIDs[1])
	assert.Contains(t, directPeers, peerIDs[4])
}

func TestCollectGroupChange_NameServerGroupLinked(t *testing.T) {
	manager, s, accountID, _, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

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

	groups, _ := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Contains(t, groups, groupIDs[0])

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

	groups, _ := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[2]})
	assert.Contains(t, groups, groupIDs[2])

	groups, _ = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Empty(t, groups)
}

func TestCollectGroupChange_NetworkRouterLinked(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

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

	groups, directPeers := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Contains(t, groups, groupIDs[0])
	assert.Contains(t, directPeers, peerIDs[3])

	groups, directPeers = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[1]})
	assert.Empty(t, groups)
	assert.Empty(t, directPeers)
}

func TestCollectGroupChange_MultipleEntities(t *testing.T) {
	manager, s, accountID, _, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

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

	groups, directPeers := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Contains(t, groups, groupIDs[0])
	assert.Contains(t, groups, groupIDs[1])
	assert.NotContains(t, groups, groupIDs[2])
	assert.NotContains(t, groups, groupIDs[3])
	assert.Empty(t, directPeers)

	groups, directPeers = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[3]})
	assert.Contains(t, groups, groupIDs[2])
	assert.Contains(t, groups, groupIDs[3])
	assert.NotContains(t, groups, groupIDs[0])
	assert.NotContains(t, groups, groupIDs[1])
	assert.Empty(t, directPeers)
}

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

func TestResolvePeerIDs_GroupsOnly(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	result := manager.resolvePeerIDs(ctx, s, accountID, []string{groupIDs[0], groupIDs[1]}, nil)
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1]}, result)
}

func TestResolvePeerIDs_WithDirectPeers(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	result := manager.resolvePeerIDs(ctx, s, accountID, []string{groupIDs[0]}, []string{peerIDs[2]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[2]}, result)
}

func TestResolvePeerIDs_Deduplication(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

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

func TestResolveAffectedPeers_NoPoliciesOrRoutes(t *testing.T) {
	manager, s, accountID, peerIDs, _ := setupAffectedPeersTest(t)
	ctx := context.Background()

	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.Empty(t, result)
}

func TestResolveAffectedPeers_PolicyBetweenTwoGroups(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

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

	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1]}, result)

	result = manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[1]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1]}, result)

	result = manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[2]})
	assert.Empty(t, result)
}

func TestResolveAffectedPeers_PolicyThreeGroups(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

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

	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1], peerIDs[2]}, result)
}

func TestResolveAffectedPeers_RoutePeerGroups(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

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

	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1]}, result)

	result = manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[1]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1]}, result)

	result = manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[2]})
	assert.Empty(t, result)
}

func TestResolveAffectedPeers_RouteWithDirectPeer(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

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

	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[1]})
	assert.ElementsMatch(t, []string{peerIDs[1], peerIDs[4]}, result)
}

func TestResolveAffectedPeers_NetworkRouter(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

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

	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[3]}, result)
}

func TestResolveAffectedPeers_NameServerGroup(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

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

	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.Contains(t, result, peerIDs[0])
}

func TestResolveAffectedPeers_DNSSettings(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	err := manager.SaveDNSSettings(ctx, accountID, userID, &types.DNSSettings{
		DisabledManagementGroups: []string{groupIDs[0]},
	})
	require.NoError(t, err)

	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.Contains(t, result, peerIDs[0])
}

func TestResolveAffectedPeers_PeerInMultipleGroups(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	err := manager.GroupAddPeer(ctx, accountID, groupIDs[1], peerIDs[0])
	require.NoError(t, err)

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

	// peer0 is in group0 AND group1, so both policies apply
	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1], peerIDs[2], peerIDs[3]}, result)
}

func TestResolveAffectedPeers_MultipleChangedPeers(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

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

	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0], peerIDs[2]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1], peerIDs[2], peerIDs[3]}, result)
}

func TestResolveAffectedPeers_SharedGroupAcrossPolicyAndRoute(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

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

	// group0 is shared: policy gives peer0+peer1, route gives peer0+peer2
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

func TestAffectedPeers_GroupUpdateOnlyAffectsLinkedPeers(t *testing.T) {
	manager, updateManager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)
	ctx := context.Background()
	accountID := account.Id

	policies, err := manager.Store.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)
	for _, p := range policies {
		err := manager.Store.DeletePolicy(ctx, accountID, p.ID)
		require.NoError(t, err)
	}

	for _, g := range []*types.Group{
		{ID: "ap-grpA", Name: "AP-A", Peers: []string{peer1.ID}},
		{ID: "ap-grpB", Name: "AP-B", Peers: []string{peer2.ID}},
		{ID: "ap-grpC", Name: "AP-C", Peers: []string{peer3.ID}},
	} {
		err := manager.CreateGroup(ctx, accountID, userID, g)
		require.NoError(t, err)
	}

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

	updMsg1 := updateManager.CreateChannel(ctx, peer1.ID)
	updMsg2 := updateManager.CreateChannel(ctx, peer2.ID)
	updMsg3 := updateManager.CreateChannel(ctx, peer3.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(ctx, peer1.ID)
		updateManager.CloseChannel(ctx, peer2.ID)
		updateManager.CloseChannel(ctx, peer3.ID)
	})

	result := manager.resolveAffectedPeersForPeerChanges(ctx, manager.Store, accountID, []string{peer1.ID})
	assert.ElementsMatch(t, []string{peer1.ID, peer2.ID}, result)

	// Adding peer3 to grpA makes it part of the policy, so all 3 peers get updated
	t.Run("group change updates all peers in policy groups", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg1)
			peerShouldReceiveUpdate(t, updMsg2)
			peerShouldReceiveUpdate(t, updMsg3)
			close(done)
		}()

		err := manager.UpdateGroup(ctx, accountID, userID, &types.Group{
			ID:    "ap-grpA",
			Name:  "AP-A",
			Peers: []string{peer1.ID, peer3.ID},
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

	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.Empty(t, result)
}

func TestCollectPostureCheckAffected_NoMatch(t *testing.T) {
	_, s, accountID, _, _ := setupAffectedPeersTest(t)
	ctx := context.Background()

	groups, directPeers := collectPostureCheckAffectedGroupsAndPeers(ctx, s, accountID, "nonexistent-check")
	assert.Empty(t, groups)
	assert.Empty(t, directPeers)
}

func TestAffectedPeers_IsolatedPolicies(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

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

	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1]}, result)
	assert.NotContains(t, result, peerIDs[2])
	assert.NotContains(t, result, peerIDs[3])

	result = manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[2]})
	assert.ElementsMatch(t, []string{peerIDs[2], peerIDs[3]}, result)
	assert.NotContains(t, result, peerIDs[0])
	assert.NotContains(t, result, peerIDs[1])

	result = manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[4]})
	assert.Empty(t, result)
}

func TestAffectedPeers_IsolatedRouteAndPolicy(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

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

	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1]}, result)
	assert.NotContains(t, result, peerIDs[2])
	assert.NotContains(t, result, peerIDs[3])

	result = manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[2]})
	assert.ElementsMatch(t, []string{peerIDs[2], peerIDs[3]}, result)
	assert.NotContains(t, result, peerIDs[0])
	assert.NotContains(t, result, peerIDs[1])
}

func TestResolveAffectedPeers_NoDuplicates(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	err := manager.GroupAddPeer(ctx, accountID, groupIDs[1], peerIDs[0])
	require.NoError(t, err)
	err = manager.GroupAddPeer(ctx, accountID, groupIDs[2], peerIDs[0])
	require.NoError(t, err)

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
	count := 0
	for _, id := range result {
		if id == peerIDs[0] {
			count++
		}
	}
	assert.Equal(t, 1, count, "peer0 should appear exactly once")
}

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
