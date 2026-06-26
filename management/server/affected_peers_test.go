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
	rpservice "github.com/netbirdio/netbird/management/internals/modules/reverseproxy/service"
	"github.com/netbirdio/netbird/management/server/affectedpeers"
	routerTypes "github.com/netbirdio/netbird/management/server/networks/routers/types"
	networkTypes "github.com/netbirdio/netbird/management/server/networks/types"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/posture"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/route"
)

// resolveAffected is a test helper for the resolver's Load+Expand, used where a
// test asserts on the fully expanded affected peer set.
func resolveAffected(t *testing.T, s store.Store, accountID string, change affectedpeers.Change) []string {
	t.Helper()
	ctx := context.Background()
	snap, err := affectedpeers.Load(ctx, s, accountID, change)
	require.NoError(t, err)
	return snap.Expand(ctx, accountID, change)
}

// Thin test adapters over affectedpeers.Collect, preserving the (groups, peers)
// shape these tests assert on after the resolver was unified.
func collectGroupChangeAffectedGroups(ctx context.Context, s store.Store, accountID string, changedGroupIDs []string) ([]string, []string) {
	return affectedpeers.Collect(ctx, s, accountID, affectedpeers.Change{ChangedGroupIDs: changedGroupIDs})
}

func collectPeerChangeAffectedGroups(ctx context.Context, s store.Store, accountID string, changedGroupIDs, changedPeerIDs []string) ([]string, []string) {
	return affectedpeers.Collect(ctx, s, accountID, affectedpeers.Change{ChangedGroupIDs: changedGroupIDs, ChangedPeerIDs: changedPeerIDs})
}

func collectPostureCheckAffectedGroupsAndPeers(ctx context.Context, s store.Store, accountID, postureCheckID string) ([]string, []string) {
	return affectedpeers.Collect(ctx, s, accountID, affectedpeers.Change{PostureCheckIDs: []string{postureCheckID}})
}

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

func TestCollectGroupChange_PolicyWithNonPeerResource_NoDirectPeers(t *testing.T) {
	manager, s, accountID, _, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	_, err := manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:        true,
				Sources:        []string{groupIDs[0]},
				SourceResource: types.Resource{ID: "some-domain", Type: types.ResourceTypeDomain},
				Destinations:   []string{groupIDs[1]},
				Action:         types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	groups, directPeers := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Contains(t, groups, groupIDs[0])
	assert.Contains(t, groups, groupIDs[1])
	assert.Empty(t, directPeers, "non-peer resources should not produce direct peer IDs")
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

	err = manager.Store.CreateNetworkRouter(ctx, &routerTypes.NetworkRouter{
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

func TestCollectGroupChange_NetworkRouterPeerOnlyNoGroups(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	net1 := &networkTypes.Network{
		ID:        "net-peer-only",
		AccountID: accountID,
		Name:      "peer-only-network",
	}
	err := manager.Store.SaveNetwork(ctx, net1)
	require.NoError(t, err)

	// Router with only a direct peer, no PeerGroups
	err = manager.Store.CreateNetworkRouter(ctx, &routerTypes.NetworkRouter{
		ID:        "router-peer-only",
		NetworkID: net1.ID,
		AccountID: accountID,
		Peer:      peerIDs[4],
	})
	require.NoError(t, err)

	// None of the groups should match since router has no PeerGroups
	for i := 0; i < 5; i++ {
		groups, directPeers := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[i]})
		assert.Empty(t, groups, "group%d should not match router with only direct peer", i)
		assert.Empty(t, directPeers, "group%d should not produce direct peers", i)
	}
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

func TestCollectGroupChange_MultipleNameServerGroups_OnlyLinkedAffected(t *testing.T) {
	manager, s, accountID, _, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Create two nameserver groups using different groups
	_, err := manager.CreateNameServerGroup(ctx, accountID, "ns-a", "NS-A",
		[]nbdns.NameServer{{
			IP:     netip.MustParseAddr("1.1.1.1"),
			NSType: nbdns.UDPNameServerType,
			Port:   nbdns.DefaultDNSPort,
		}},
		[]string{groupIDs[0]},
		true, nil, true, userID, false,
	)
	require.NoError(t, err)

	_, err = manager.CreateNameServerGroup(ctx, accountID, "ns-b", "NS-B",
		[]nbdns.NameServer{{
			IP:     netip.MustParseAddr("8.8.8.8"),
			NSType: nbdns.UDPNameServerType,
			Port:   nbdns.DefaultDNSPort,
		}},
		[]string{groupIDs[2]},
		true, nil, true, userID, false,
	)
	require.NoError(t, err)

	// Changing group0 should only find group0 (from ns-a), not group2 (from ns-b)
	groups, _ := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Contains(t, groups, groupIDs[0])
	assert.NotContains(t, groups, groupIDs[2])

	groups, _ = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[2]})
	assert.Contains(t, groups, groupIDs[2])
	assert.NotContains(t, groups, groupIDs[0])

	// Unrelated group
	groups, _ = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[4]})
	assert.Empty(t, groups)
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

func TestResolveAffectedPeers_RouteWithAccessControlGroups(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	_, err := manager.CreateRoute(ctx, accountID,
		netip.MustParsePrefix("10.7.0.0/24"),
		route.IPv4Network,
		nil,
		"",
		[]string{groupIDs[0]},
		"acl route",
		"aclnet",
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

	// peer2 is only in AccessControlGroups, still should be affected
	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[2]})
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1], peerIDs[2]}, result)

	// peer3 is unrelated
	result = manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[3]})
	assert.Empty(t, result)
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

	err = manager.Store.CreateNetworkRouter(ctx, &routerTypes.NetworkRouter{
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

func TestCollectPostureCheckAffected_LinkedToPolicy(t *testing.T) {
	manager, s, accountID, _, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Create the posture check in the store so the policy validation keeps the reference.
	err := s.SavePostureChecks(ctx, &posture.Checks{
		ID:        "pc-1",
		Name:      "test-posture-check",
		AccountID: accountID,
	})
	require.NoError(t, err)

	policy, err := manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled:             true,
		SourcePostureChecks: []string{"pc-1"},
		Rules: []*types.PolicyRule{
			{
				Enabled:      true,
				Sources:      []string{groupIDs[0]},
				Destinations: []string{groupIDs[1]},
				Action:       types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)
	_ = policy

	groups, directPeers := collectPostureCheckAffectedGroupsAndPeers(ctx, s, accountID, "pc-1")
	assert.Contains(t, groups, groupIDs[0])
	assert.Contains(t, groups, groupIDs[1])
	assert.Empty(t, directPeers)

	// Different posture check ID should not match
	groups, directPeers = collectPostureCheckAffectedGroupsAndPeers(ctx, s, accountID, "pc-other")
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
}

func TestAffectedPeers_UnlinkedGroupChange_NoUpdates(t *testing.T) {
	manager, s, accountID, peerIDs, _ := setupAffectedPeersTest(t)
	ctx := context.Background()

	result := manager.resolveAffectedPeersForPeerChanges(ctx, s, accountID, []string{peerIDs[0]})
	assert.Empty(t, result)
}

// TestAffectedPeers_PolicyChange_UnrelatedPeerNoUpdate verifies that creating/deleting a
// policy only sends updates to peers in the policy's groups, not to unrelated peers.
func TestAffectedPeers_PolicyChange_UnrelatedPeerNoUpdate(t *testing.T) {
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
		{ID: "pol-grpA", Name: "Pol-A", Peers: []string{peer1.ID}},
		{ID: "pol-grpB", Name: "Pol-B", Peers: []string{peer2.ID}},
		{ID: "pol-grpC", Name: "Pol-C", Peers: []string{peer3.ID}},
	} {
		err := manager.CreateGroup(ctx, accountID, userID, g)
		require.NoError(t, err)
	}

	updMsg1 := updateManager.CreateChannel(ctx, peer1.ID)
	updMsg2 := updateManager.CreateChannel(ctx, peer2.ID)
	updMsg3 := updateManager.CreateChannel(ctx, peer3.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(ctx, peer1.ID)
		updateManager.CloseChannel(ctx, peer2.ID)
		updateManager.CloseChannel(ctx, peer3.ID)
	})

	t.Run("create policy only affects linked peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg1)
			peerShouldReceiveUpdate(t, updMsg2)
			peerShouldNotReceiveUpdate(t, updMsg3)
			close(done)
		}()

		_, err := manager.SavePolicy(ctx, accountID, userID, &types.Policy{
			Enabled: true,
			Rules: []*types.PolicyRule{
				{
					Enabled:       true,
					Sources:       []string{"pol-grpA"},
					Destinations:  []string{"pol-grpB"},
					Bidirectional: true,
					Action:        types.PolicyTrafficActionAccept,
				},
			},
		}, true)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(peerUpdateTimeout):
			t.Error("timeout")
		}
	})
}

// TestAffectedPeers_RouteChange_UnrelatedPeerNoUpdate verifies that creating a route
// only sends updates to peers in the route's groups, not to unrelated peers.
func TestAffectedPeers_RouteChange_UnrelatedPeerNoUpdate(t *testing.T) {
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
		{ID: "rt-grpA", Name: "Rt-A", Peers: []string{peer1.ID}},
		{ID: "rt-grpB", Name: "Rt-B", Peers: []string{peer2.ID}},
		{ID: "rt-grpC", Name: "Rt-C", Peers: []string{peer3.ID}},
	} {
		err := manager.CreateGroup(ctx, accountID, userID, g)
		require.NoError(t, err)
	}

	updMsg1 := updateManager.CreateChannel(ctx, peer1.ID)
	updMsg2 := updateManager.CreateChannel(ctx, peer2.ID)
	updMsg3 := updateManager.CreateChannel(ctx, peer3.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(ctx, peer1.ID)
		updateManager.CloseChannel(ctx, peer2.ID)
		updateManager.CloseChannel(ctx, peer3.ID)
	})

	t.Run("create route only affects linked peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg1)
			peerShouldReceiveUpdate(t, updMsg2)
			peerShouldNotReceiveUpdate(t, updMsg3)
			close(done)
		}()

		_, err := manager.CreateRoute(ctx, accountID,
			netip.MustParsePrefix("10.10.0.0/24"),
			route.IPv4Network,
			nil,
			"",
			[]string{"rt-grpA"},
			"test route",
			"routenoaffect",
			false,
			9999,
			[]string{"rt-grpB"},
			nil,
			true,
			userID,
			false,
			false,
		)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(peerUpdateTimeout):
			t.Error("timeout")
		}
	})
}

// TestAffectedPeers_NameServerChange_UnrelatedPeerNoUpdate verifies that creating a
// nameserver group only sends updates to peers in its groups, not to unrelated peers.
func TestAffectedPeers_NameServerChange_UnrelatedPeerNoUpdate(t *testing.T) {
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
		{ID: "ns-grpA", Name: "NS-A", Peers: []string{peer1.ID}},
		{ID: "ns-grpB", Name: "NS-B", Peers: []string{peer2.ID}},
	} {
		err := manager.CreateGroup(ctx, accountID, userID, g)
		require.NoError(t, err)
	}

	updMsg1 := updateManager.CreateChannel(ctx, peer1.ID)
	updMsg2 := updateManager.CreateChannel(ctx, peer2.ID)
	updMsg3 := updateManager.CreateChannel(ctx, peer3.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(ctx, peer1.ID)
		updateManager.CloseChannel(ctx, peer2.ID)
		updateManager.CloseChannel(ctx, peer3.ID)
	})

	t.Run("create nameserver group only affects linked peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg1)
			peerShouldNotReceiveUpdate(t, updMsg2)
			peerShouldNotReceiveUpdate(t, updMsg3)
			close(done)
		}()

		_, err := manager.CreateNameServerGroup(ctx, accountID, "ns-unrelated", "NS Unrelated",
			[]nbdns.NameServer{{
				IP:     netip.MustParseAddr("1.1.1.1"),
				NSType: nbdns.UDPNameServerType,
				Port:   nbdns.DefaultDNSPort,
			}},
			[]string{"ns-grpA"},
			true, nil, true, userID, false,
		)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(peerUpdateTimeout):
			t.Error("timeout")
		}
	})
}

// TestAffectedPeers_DNSSettingsChange_UnrelatedPeerNoUpdate verifies that changing DNS
// settings only sends updates to peers in the affected groups, not to unrelated peers.
func TestAffectedPeers_DNSSettingsChange_UnrelatedPeerNoUpdate(t *testing.T) {
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
		{ID: "dns-grpA", Name: "DNS-A", Peers: []string{peer1.ID}},
		{ID: "dns-grpB", Name: "DNS-B", Peers: []string{peer2.ID}},
	} {
		err := manager.CreateGroup(ctx, accountID, userID, g)
		require.NoError(t, err)
	}

	updMsg1 := updateManager.CreateChannel(ctx, peer1.ID)
	updMsg2 := updateManager.CreateChannel(ctx, peer2.ID)
	updMsg3 := updateManager.CreateChannel(ctx, peer3.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(ctx, peer1.ID)
		updateManager.CloseChannel(ctx, peer2.ID)
		updateManager.CloseChannel(ctx, peer3.ID)
	})

	t.Run("dns settings change only affects linked peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg1)
			peerShouldNotReceiveUpdate(t, updMsg2)
			peerShouldNotReceiveUpdate(t, updMsg3)
			close(done)
		}()

		err := manager.SaveDNSSettings(ctx, accountID, userID, &types.DNSSettings{
			DisabledManagementGroups: []string{"dns-grpA"},
		})
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(peerUpdateTimeout):
			t.Error("timeout")
		}
	})
}

// TestAffectedPeers_UnlinkedGroupChange_NoUpdateIntegration tests the full integration:
// updating a group that is NOT referenced by any policy/route/ns/dns should not send
// updates to any peer.
func TestAffectedPeers_UnlinkedGroupChange_NoUpdateIntegration(t *testing.T) {
	manager, updateManager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)
	ctx := context.Background()
	accountID := account.Id

	policies, err := manager.Store.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)
	for _, p := range policies {
		err := manager.Store.DeletePolicy(ctx, accountID, p.ID)
		require.NoError(t, err)
	}

	err = manager.CreateGroup(ctx, accountID, userID, &types.Group{
		ID:    "unlinked-grp",
		Name:  "Unlinked",
		Peers: []string{peer1.ID},
	})
	require.NoError(t, err)

	updMsg1 := updateManager.CreateChannel(ctx, peer1.ID)
	updMsg2 := updateManager.CreateChannel(ctx, peer2.ID)
	updMsg3 := updateManager.CreateChannel(ctx, peer3.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(ctx, peer1.ID)
		updateManager.CloseChannel(ctx, peer2.ID)
		updateManager.CloseChannel(ctx, peer3.ID)
	})

	t.Run("updating unlinked group sends no peer updates", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldNotReceiveUpdate(t, updMsg1)
			peerShouldNotReceiveUpdate(t, updMsg2)
			peerShouldNotReceiveUpdate(t, updMsg3)
			close(done)
		}()

		err := manager.UpdateGroup(ctx, accountID, userID, &types.Group{
			ID:    "unlinked-grp",
			Name:  "Unlinked",
			Peers: []string{peer1.ID, peer2.ID},
		})
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(peerUpdateTimeout):
			t.Error("timeout")
		}
	})
}

// TestAffectedPeers_NetworkRouterUnlinkedPeerNoUpdate: a network router with peer
// groups updates only those groups' peers (and resource policy sources), not others.
func TestAffectedPeers_NetworkRouterUnlinkedPeerNoUpdate(t *testing.T) {
	// Delete the default policy before adding peers so AddPeer schedules no async
	// update that races with the test.
	manager, updateManager, err := createManager(t)
	require.NoError(t, err)

	ctx := context.Background()

	account, err := createAccount(manager, "nr_test_account", userID, "")
	require.NoError(t, err)
	accountID := account.Id

	policies, err := manager.Store.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)
	for _, p := range policies {
		err := manager.Store.DeletePolicy(ctx, accountID, p.ID)
		require.NoError(t, err)
	}

	setupKey, err := manager.CreateSetupKey(ctx, accountID, "test-key", types.SetupKeyReusable, time.Hour, nil, 999, userID, false, false)
	require.NoError(t, err)

	peer1 := addPeerToAccount(t, manager, accountID, setupKey.Key)
	peer2 := addPeerToAccount(t, manager, accountID, setupKey.Key)
	peer3 := addPeerToAccount(t, manager, accountID, setupKey.Key)

	for _, g := range []*types.Group{
		{ID: "nr-grpA", Name: "NR-A", Peers: []string{peer1.ID}},
		{ID: "nr-grpB", Name: "NR-B", Peers: []string{peer2.ID}},
	} {
		err := manager.CreateGroup(ctx, accountID, userID, g)
		require.NoError(t, err)
	}

	net1 := &networkTypes.Network{
		ID:        "nr-net-test",
		AccountID: accountID,
		Name:      "nr-test-network",
	}
	err = manager.Store.SaveNetwork(ctx, net1)
	require.NoError(t, err)

	err = manager.Store.CreateNetworkRouter(ctx, &routerTypes.NetworkRouter{
		ID:         "nr-router-test",
		NetworkID:  net1.ID,
		AccountID:  accountID,
		PeerGroups: []string{"nr-grpA"},
	})
	require.NoError(t, err)

	updMsg1 := updateManager.CreateChannel(ctx, peer1.ID)
	updMsg2 := updateManager.CreateChannel(ctx, peer2.ID)
	updMsg3 := updateManager.CreateChannel(ctx, peer3.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(ctx, peer1.ID)
		updateManager.CloseChannel(ctx, peer2.ID)
		updateManager.CloseChannel(ctx, peer3.ID)
	})

	t.Run("network router group change only affects linked peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg1)
			peerShouldNotReceiveUpdate(t, updMsg2)
			peerShouldReceiveUpdate(t, updMsg3)
			close(done)
		}()

		err = manager.UpdateGroup(ctx, accountID, userID, &types.Group{
			ID:    "nr-grpA",
			Name:  "NR-A",
			Peers: []string{peer1.ID, peer3.ID},
		})
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(peerUpdateTimeout):
			t.Error("timeout")
		}
	})
}

// TestAffectedPeers_IsolatedEntitiesOnlyAffectTheirPeers: with a policy (peer1<->peer2)
// and a separate route (peer3), changing one entity's groups affects only its peers.
func TestAffectedPeers_IsolatedEntitiesOnlyAffectTheirPeers(t *testing.T) {
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
		{ID: "iso-grpA", Name: "ISO-A", Peers: []string{peer1.ID}},
		{ID: "iso-grpB", Name: "ISO-B", Peers: []string{peer2.ID}},
		{ID: "iso-grpC", Name: "ISO-C", Peers: []string{peer3.ID}},
	} {
		err := manager.CreateGroup(ctx, accountID, userID, g)
		require.NoError(t, err)
	}

	_, err = manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{"iso-grpA"},
				Destinations:  []string{"iso-grpB"},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			},
		},
	}, true)
	require.NoError(t, err)

	_, err = manager.CreateRoute(ctx, accountID,
		netip.MustParsePrefix("10.20.0.0/24"),
		route.IPv4Network,
		nil,
		"",
		[]string{"iso-grpC"},
		"isolated route",
		"isonet2",
		false,
		9999,
		[]string{"iso-grpC"},
		nil,
		true,
		userID,
		false,
		false,
	)
	require.NoError(t, err)

	updMsg1 := updateManager.CreateChannel(ctx, peer1.ID)
	updMsg2 := updateManager.CreateChannel(ctx, peer2.ID)
	updMsg3 := updateManager.CreateChannel(ctx, peer3.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(ctx, peer1.ID)
		updateManager.CloseChannel(ctx, peer2.ID)
		updateManager.CloseChannel(ctx, peer3.ID)
	})

	// The setup policy/route above dispatch affected-peer updates asynchronously;
	// drain any in-flight ones so the assertions only observe the UpdateGroup below.
	settleAffectedUpdates(updMsg1, updMsg2, updMsg3)

	t.Run("policy group change does not affect route-only peer", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg1)
			peerShouldReceiveUpdate(t, updMsg2)
			peerShouldNotReceiveUpdate(t, updMsg3)
			close(done)
		}()

		err := manager.UpdateGroup(ctx, accountID, userID, &types.Group{
			ID:    "iso-grpA",
			Name:  "ISO-A-updated",
			Peers: []string{peer1.ID},
		})
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(peerUpdateTimeout):
			t.Error("timeout")
		}
	})
}

// TestAffectedPeers_DeleteRoute_UnrelatedPeerNoUpdate verifies that deleting a route
// only sends updates to peers in the route's groups.
func TestAffectedPeers_DeleteRoute_UnrelatedPeerNoUpdate(t *testing.T) {
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
		{ID: "del-rt-grpA", Name: "Del-Rt-A", Peers: []string{peer1.ID}},
		{ID: "del-rt-grpB", Name: "Del-Rt-B", Peers: []string{peer2.ID}},
	} {
		err := manager.CreateGroup(ctx, accountID, userID, g)
		require.NoError(t, err)
	}

	newRoute, err := manager.CreateRoute(ctx, accountID,
		netip.MustParsePrefix("10.30.0.0/24"),
		route.IPv4Network,
		nil,
		"",
		[]string{"del-rt-grpA"},
		"deletable route",
		"delnet",
		false,
		9999,
		[]string{"del-rt-grpB"},
		nil,
		true,
		userID,
		false,
		false,
	)
	require.NoError(t, err)

	updMsg1 := updateManager.CreateChannel(ctx, peer1.ID)
	updMsg2 := updateManager.CreateChannel(ctx, peer2.ID)
	updMsg3 := updateManager.CreateChannel(ctx, peer3.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(ctx, peer1.ID)
		updateManager.CloseChannel(ctx, peer2.ID)
		updateManager.CloseChannel(ctx, peer3.ID)
	})

	t.Run("delete route only affects linked peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg1)
			peerShouldReceiveUpdate(t, updMsg2)
			peerShouldNotReceiveUpdate(t, updMsg3)
			close(done)
		}()

		err := manager.DeleteRoute(ctx, accountID, newRoute.ID, userID)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(peerUpdateTimeout):
			t.Error("timeout")
		}
	})
}

// TestAffectedPeers_DeletePolicy_UnrelatedPeerNoUpdate verifies that deleting a policy
// only sends updates to peers in the policy's groups.
func TestAffectedPeers_DeletePolicy_UnrelatedPeerNoUpdate(t *testing.T) {
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
		{ID: "del-pol-grpA", Name: "Del-Pol-A", Peers: []string{peer1.ID}},
		{ID: "del-pol-grpB", Name: "Del-Pol-B", Peers: []string{peer2.ID}},
	} {
		err := manager.CreateGroup(ctx, accountID, userID, g)
		require.NoError(t, err)
	}

	policy, err := manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{
			{
				Enabled:       true,
				Sources:       []string{"del-pol-grpA"},
				Destinations:  []string{"del-pol-grpB"},
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

	t.Run("delete policy only affects linked peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg1)
			peerShouldReceiveUpdate(t, updMsg2)
			peerShouldNotReceiveUpdate(t, updMsg3)
			close(done)
		}()

		err := manager.DeletePolicy(ctx, accountID, policy.ID, userID)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(peerUpdateTimeout):
			t.Error("timeout")
		}
	})
}

// TestAffectedPeers_DeleteNameServer_UnrelatedPeerNoUpdate verifies that deleting a
// nameserver group only sends updates to peers in its groups.
func TestAffectedPeers_DeleteNameServer_UnrelatedPeerNoUpdate(t *testing.T) {
	manager, updateManager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)
	ctx := context.Background()
	accountID := account.Id

	policies, err := manager.Store.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)
	for _, p := range policies {
		err := manager.Store.DeletePolicy(ctx, accountID, p.ID)
		require.NoError(t, err)
	}

	err = manager.CreateGroup(ctx, accountID, userID, &types.Group{
		ID:    "del-ns-grpA",
		Name:  "Del-NS-A",
		Peers: []string{peer1.ID},
	})
	require.NoError(t, err)

	nsGroup, err := manager.CreateNameServerGroup(ctx, accountID, "del-ns", "Del NS",
		[]nbdns.NameServer{{
			IP:     netip.MustParseAddr("8.8.4.4"),
			NSType: nbdns.UDPNameServerType,
			Port:   nbdns.DefaultDNSPort,
		}},
		[]string{"del-ns-grpA"},
		true, nil, true, userID, false,
	)
	require.NoError(t, err)

	updMsg1 := updateManager.CreateChannel(ctx, peer1.ID)
	updMsg2 := updateManager.CreateChannel(ctx, peer2.ID)
	updMsg3 := updateManager.CreateChannel(ctx, peer3.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(ctx, peer1.ID)
		updateManager.CloseChannel(ctx, peer2.ID)
		updateManager.CloseChannel(ctx, peer3.ID)
	})

	t.Run("delete nameserver group only affects linked peers", func(t *testing.T) {
		done := make(chan struct{})
		go func() {
			peerShouldReceiveUpdate(t, updMsg1)
			peerShouldNotReceiveUpdate(t, updMsg2)
			peerShouldNotReceiveUpdate(t, updMsg3)
			close(done)
		}()

		err := manager.DeleteNameServerGroup(ctx, accountID, nsGroup.ID, userID)
		assert.NoError(t, err)

		select {
		case <-done:
		case <-time.After(peerUpdateTimeout):
			t.Error("timeout")
		}
	})
}

func addPeerToAccount(t *testing.T, manager *DefaultAccountManager, _, setupKeyKey string) *nbpeer.Peer {
	t.Helper()

	key, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	peer, _, _, _, err := manager.AddPeer(context.Background(), "", setupKeyKey, "", &nbpeer.Peer{
		Key:  key.PublicKey().String(),
		Meta: nbpeer.PeerSystemMeta{Hostname: key.PublicKey().String()},
	}, false)
	require.NoError(t, err)
	return peer
}

// markPeerAsProxy flips an existing peer's ProxyMeta to mark it as an embedded
// proxy peer in the given cluster.
func markPeerAsProxy(t *testing.T, s store.Store, accountID, peerID, cluster string) {
	t.Helper()
	ctx := context.Background()
	peer, err := s.GetPeerByID(ctx, store.LockingStrengthNone, accountID, peerID)
	require.NoError(t, err)
	peer.ProxyMeta = nbpeer.ProxyMeta{Embedded: true, Cluster: cluster}
	require.NoError(t, s.SavePeer(ctx, accountID, peer))
}

// createServiceWithTargets persists a service with the given cluster and targets
// directly in the store, bypassing the proxy-service manager (which would also
// run cluster derivation and trigger UpdateAccountPeers).
func createServiceWithTargets(t *testing.T, s store.Store, accountID, cluster string, targets []*rpservice.Target) *rpservice.Service {
	t.Helper()
	svc := &rpservice.Service{
		AccountID:    accountID,
		Name:         fmt.Sprintf("svc-%s", cluster),
		Domain:       fmt.Sprintf("%s.example.com", cluster),
		ProxyCluster: cluster,
		Enabled:      true,
		Mode:         "tcp",
		Targets:      targets,
	}
	svc.InitNewRecord()
	for _, target := range targets {
		target.AccountID = accountID
		target.ServiceID = svc.ID
	}
	require.NoError(t, s.CreateService(context.Background(), svc))
	return svc
}

func TestCollectAffectedFromProxyServices_TargetPeerChanged(t *testing.T) {
	manager, s, accountID, peerIDs, _ := setupAffectedPeersTest(t)
	ctx := context.Background()

	cluster := "cluster-a"
	markPeerAsProxy(t, s, accountID, peerIDs[0], cluster)

	createServiceWithTargets(t, s, accountID, cluster, []*rpservice.Target{
		{TargetType: rpservice.TargetTypePeer, TargetId: peerIDs[1], Enabled: true, Port: 80, Protocol: "tcp"},
	})

	_, directPeers := collectPeerChangeAffectedGroups(ctx, manager.Store, accountID, nil, []string{peerIDs[1]})
	assert.Contains(t, directPeers, peerIDs[0], "proxy peer must be refreshed when its target peer changes")
	assert.Contains(t, directPeers, peerIDs[1], "target peer must be refreshed")
}

func TestCollectAffectedFromProxyServices_ProxyPeerChanged(t *testing.T) {
	manager, s, accountID, peerIDs, _ := setupAffectedPeersTest(t)
	ctx := context.Background()

	cluster := "cluster-a"
	markPeerAsProxy(t, s, accountID, peerIDs[0], cluster)

	createServiceWithTargets(t, s, accountID, cluster, []*rpservice.Target{
		{TargetType: rpservice.TargetTypePeer, TargetId: peerIDs[1], Enabled: true, Port: 80, Protocol: "tcp"},
		{TargetType: rpservice.TargetTypePeer, TargetId: peerIDs[2], Enabled: true, Port: 80, Protocol: "tcp"},
	})

	_, directPeers := collectPeerChangeAffectedGroups(ctx, manager.Store, accountID, nil, []string{peerIDs[0]})
	assert.Contains(t, directPeers, peerIDs[0], "changed proxy peer is itself refreshed")
	assert.Contains(t, directPeers, peerIDs[1], "target peer 1 must be refreshed when proxy peer changes")
	assert.Contains(t, directPeers, peerIDs[2], "target peer 2 must be refreshed when proxy peer changes")
}

func TestCollectAffectedFromProxyServices_GroupContainingTargetPeerChanged(t *testing.T) {
	manager, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	cluster := "cluster-a"
	markPeerAsProxy(t, s, accountID, peerIDs[0], cluster)

	createServiceWithTargets(t, s, accountID, cluster, []*rpservice.Target{
		{TargetType: rpservice.TargetTypePeer, TargetId: peerIDs[1], Enabled: true, Port: 80, Protocol: "tcp"},
	})

	_, directPeers := collectPeerChangeAffectedGroups(ctx, manager.Store, accountID, []string{groupIDs[1]}, nil)
	assert.Contains(t, directPeers, peerIDs[0], "proxy peer must be refreshed when a group containing its target peer changes")
	assert.Contains(t, directPeers, peerIDs[1], "target peer must be refreshed")
}

func TestCollectAffectedFromProxyServices_DisabledServiceStillMatches(t *testing.T) {
	manager, s, accountID, peerIDs, _ := setupAffectedPeersTest(t)
	ctx := context.Background()

	cluster := "cluster-a"
	markPeerAsProxy(t, s, accountID, peerIDs[0], cluster)

	svc := &rpservice.Service{
		AccountID:    accountID,
		Name:         "disabled-svc",
		Domain:       "disabled.example.com",
		ProxyCluster: cluster,
		Enabled:      false,
		Mode:         "tcp",
		Targets: []*rpservice.Target{
			{TargetType: rpservice.TargetTypePeer, TargetId: peerIDs[1], Enabled: false, Port: 80, Protocol: "tcp"},
		},
	}
	svc.InitNewRecord()
	for _, target := range svc.Targets {
		target.AccountID = accountID
		target.ServiceID = svc.ID
	}
	require.NoError(t, s.CreateService(ctx, svc))

	_, directPeers := collectPeerChangeAffectedGroups(ctx, manager.Store, accountID, nil, []string{peerIDs[1]})
	assert.Contains(t, directPeers, peerIDs[0], "disabled service should still trigger a refresh so peers are ready when re-enabled")
	assert.Contains(t, directPeers, peerIDs[1], "disabled target should still trigger a refresh")
}

func TestCollectAffectedFromProxyServices_NonPeerTargetType(t *testing.T) {
	manager, s, accountID, peerIDs, _ := setupAffectedPeersTest(t)
	ctx := context.Background()

	cluster := "cluster-a"
	markPeerAsProxy(t, s, accountID, peerIDs[0], cluster)

	createServiceWithTargets(t, s, accountID, cluster, []*rpservice.Target{
		{TargetType: rpservice.TargetTypeHost, TargetId: "10.0.0.1", Host: "10.0.0.1", Enabled: true, Port: 80, Protocol: "tcp"},
	})

	_, directPeers := collectPeerChangeAffectedGroups(ctx, manager.Store, accountID, nil, []string{peerIDs[0]})
	assert.Contains(t, directPeers, peerIDs[0], "host target service still refreshes its proxy peer when the proxy peer changes")
	assert.NotContains(t, directPeers, "10.0.0.1", "non-peer target ids must not appear as affected peer IDs")
}
