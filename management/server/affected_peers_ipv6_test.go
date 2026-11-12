package server

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

const (
	ipv6GroupA = "ipv6-grp-a"
	ipv6GroupB = "ipv6-grp-b"
	ipv6GroupC = "ipv6-grp-c"
	ipv6GroupD = "ipv6-grp-d"
)

// ipv6AffectedTest holds three peers: peer1 in group A, peer2 in group B, peer3 in
// group C, with a single A<->B policy. peer3 is unrelated to peer1 and peer2. Group D
// is empty and referenced by nothing.
type ipv6AffectedTest struct {
	manager                   *DefaultAccountManager
	accountID                 string
	peer1, peer2, peer3       *nbpeer.Peer
	updMsg1, updMsg2, updMsg3 <-chan *network_map.UpdateMessage
}

func setupIPv6AffectedTest(t *testing.T, ipv6Groups []string) *ipv6AffectedTest {
	t.Helper()

	manager, updateManager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)
	ctx := context.Background()
	accountID := account.Id

	policies, err := manager.Store.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)
	for _, p := range policies {
		require.NoError(t, manager.Store.DeletePolicy(ctx, accountID, p.ID))
	}

	for _, g := range []*types.Group{
		{ID: ipv6GroupA, Name: "IPv6-A", Peers: []string{peer1.ID}},
		{ID: ipv6GroupB, Name: "IPv6-B", Peers: []string{peer2.ID}},
		{ID: ipv6GroupC, Name: "IPv6-C", Peers: []string{peer3.ID}},
		{ID: ipv6GroupD, Name: "IPv6-D"},
	} {
		require.NoError(t, manager.CreateGroup(ctx, accountID, userID, g))
	}

	_, err = manager.SavePolicy(ctx, accountID, userID, &types.Policy{
		Enabled: true,
		Rules: []*types.PolicyRule{{
			Enabled:       true,
			Sources:       []string{ipv6GroupA},
			Destinations:  []string{ipv6GroupB},
			Bidirectional: true,
			Action:        types.PolicyTrafficActionAccept,
		}},
	}, true)
	require.NoError(t, err)

	// New accounts enable IPv6 for the All group; start from the requested groups.
	updateIPv6TestSettings(t, manager, accountID, func(s *types.Settings) {
		s.IPv6EnabledGroups = ipv6Groups
	})

	tc := &ipv6AffectedTest{
		manager:   manager,
		accountID: accountID,
		peer1:     peer1,
		peer2:     peer2,
		peer3:     peer3,
	}
	tc.updMsg1 = updateManager.CreateChannel(ctx, peer1.ID)
	tc.updMsg2 = updateManager.CreateChannel(ctx, peer2.ID)
	tc.updMsg3 = updateManager.CreateChannel(ctx, peer3.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(ctx, peer1.ID)
		updateManager.CloseChannel(ctx, peer2.ID)
		updateManager.CloseChannel(ctx, peer3.ID)
	})

	// The setup changes above dispatch asynchronously and can land after the
	// channels open, so drop them before the test acts.
	drainPeerUpdates(tc.updMsg1)
	drainPeerUpdates(tc.updMsg2)
	drainPeerUpdates(tc.updMsg3)

	return tc
}

// updateIPv6TestSettings applies mutate to a copy of the current settings, so only
// the mutated fields differ from what is stored.
func updateIPv6TestSettings(t *testing.T, manager *DefaultAccountManager, accountID string, mutate func(*types.Settings)) {
	t.Helper()
	ctx := context.Background()

	current, err := manager.Store.GetAccountSettings(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)

	updated := current.Copy()
	mutate(updated)

	_, err = manager.UpdateAccountSettings(ctx, accountID, userID, updated)
	require.NoError(t, err)
}

func (tc *ipv6AffectedTest) peerIPv6(t *testing.T, peerID string) netip.Addr {
	t.Helper()
	peer, err := tc.manager.Store.GetPeerByID(context.Background(), store.LockingStrengthNone, tc.accountID, peerID)
	require.NoError(t, err)
	return peer.IPv6
}

func TestAffectedPeers_IPv6GroupEnabled_RefreshesOnlyReachablePeers(t *testing.T) {
	tc := setupIPv6AffectedTest(t, nil)

	updateIPv6TestSettings(t, tc.manager, tc.accountID, func(s *types.Settings) {
		s.IPv6EnabledGroups = []string{ipv6GroupA}
	})
	require.True(t, tc.peerIPv6(t, tc.peer1.ID).IsValid(), "peer1 should get an IPv6 address")

	peerShouldReceiveUpdate(t, tc.updMsg1)
	peerShouldReceiveUpdate(t, tc.updMsg2)
	peerShouldNotReceiveUpdate(t, tc.updMsg3)
}

func TestAffectedPeers_IPv6GroupDisabled_RefreshesOnlyReachablePeers(t *testing.T) {
	tc := setupIPv6AffectedTest(t, []string{ipv6GroupA})
	require.True(t, tc.peerIPv6(t, tc.peer1.ID).IsValid(), "peer1 should start with an IPv6 address")

	updateIPv6TestSettings(t, tc.manager, tc.accountID, func(s *types.Settings) {
		s.IPv6EnabledGroups = []string{}
	})
	require.False(t, tc.peerIPv6(t, tc.peer1.ID).IsValid(), "peer1 should lose its IPv6 address")

	peerShouldReceiveUpdate(t, tc.updMsg1)
	peerShouldReceiveUpdate(t, tc.updMsg2)
	peerShouldNotReceiveUpdate(t, tc.updMsg3)
}

// Widening the IPv6 range keeps peer addresses, but each holder's interface prefix
// comes from the range, so holders refresh while peers that only reach them do not.
func TestAffectedPeers_IPv6RangeWidened_RefreshesAddressHolders(t *testing.T) {
	tc := setupIPv6AffectedTest(t, []string{ipv6GroupA})
	oldIPv6 := tc.peerIPv6(t, tc.peer1.ID)
	require.True(t, oldIPv6.IsValid(), "peer1 should start with an IPv6 address")

	// The range is allocated on the account network; settings may leave it empty.
	network, err := tc.manager.Store.GetAccountNetwork(context.Background(), store.LockingStrengthNone, tc.accountID)
	require.NoError(t, err)
	current := prefixFromIPNet(network.NetV6)
	require.True(t, current.IsValid(), "account should have an IPv6 range")
	widened := netip.PrefixFrom(current.Addr(), current.Bits()-8).Masked()

	updateIPv6TestSettings(t, tc.manager, tc.accountID, func(s *types.Settings) {
		s.NetworkRangeV6 = widened
	})
	require.Equal(t, oldIPv6, tc.peerIPv6(t, tc.peer1.ID), "peer1 should keep its address inside the widened range")

	peerShouldReceiveUpdate(t, tc.updMsg1)
	peerShouldNotReceiveUpdate(t, tc.updMsg2)
	peerShouldNotReceiveUpdate(t, tc.updMsg3)
}

func TestAffectedPeers_IPv4RangeChange_RefreshesWholeAccount(t *testing.T) {
	tc := setupIPv6AffectedTest(t, nil)

	updateIPv6TestSettings(t, tc.manager, tc.accountID, func(s *types.Settings) {
		s.NetworkRange = netip.MustParsePrefix("100.70.0.0/16")
	})

	peerShouldReceiveUpdate(t, tc.updMsg1)
	peerShouldReceiveUpdate(t, tc.updMsg2)
	peerShouldReceiveUpdate(t, tc.updMsg3)
}

func TestAffectedPeers_IPv6WithAccountWideChange_RefreshesWholeAccount(t *testing.T) {
	tc := setupIPv6AffectedTest(t, nil)

	updateIPv6TestSettings(t, tc.manager, tc.accountID, func(s *types.Settings) {
		s.IPv6EnabledGroups = []string{ipv6GroupA}
		s.LazyConnectionEnabled = !s.LazyConnectionEnabled
	})

	peerShouldReceiveUpdate(t, tc.updMsg1)
	peerShouldReceiveUpdate(t, tc.updMsg2)
	peerShouldReceiveUpdate(t, tc.updMsg3)
}

// Joining an IPv6-enabled group that no policy references gives peer1 an address.
// peer2 reaches peer1 through group A, not through the joined group, and must still
// learn the new address.
func TestAffectedPeers_GroupAddPeerIPv6_RefreshesPeersReachingThroughOtherGroups(t *testing.T) {
	tc := setupIPv6AffectedTest(t, []string{ipv6GroupD})

	require.NoError(t, tc.manager.GroupAddPeer(context.Background(), tc.accountID, ipv6GroupD, tc.peer1.ID))
	require.True(t, tc.peerIPv6(t, tc.peer1.ID).IsValid(), "peer1 should get an IPv6 address")

	peerShouldReceiveUpdate(t, tc.updMsg1)
	peerShouldReceiveUpdate(t, tc.updMsg2)
	peerShouldNotReceiveUpdate(t, tc.updMsg3)
}

func TestAffectedPeers_UpdateGroupIPv6_RefreshesPeersReachingThroughOtherGroups(t *testing.T) {
	tc := setupIPv6AffectedTest(t, []string{ipv6GroupD})

	require.NoError(t, tc.manager.UpdateGroup(context.Background(), tc.accountID, userID, &types.Group{
		ID:    ipv6GroupD,
		Name:  "IPv6-D",
		Peers: []string{tc.peer1.ID},
	}))
	require.True(t, tc.peerIPv6(t, tc.peer1.ID).IsValid(), "peer1 should get an IPv6 address")

	peerShouldReceiveUpdate(t, tc.updMsg1)
	peerShouldReceiveUpdate(t, tc.updMsg2)
	peerShouldNotReceiveUpdate(t, tc.updMsg3)
}

// Deleting an IPv6-enabled group removes its members' addresses after the
// pre-delete snapshot was taken.
func TestAffectedPeers_DeleteIPv6Group_RefreshesFormerMembersAndReachablePeers(t *testing.T) {
	tc := setupIPv6AffectedTest(t, []string{ipv6GroupD})
	ctx := context.Background()

	require.NoError(t, tc.manager.GroupAddPeer(ctx, tc.accountID, ipv6GroupD, tc.peer1.ID))
	require.True(t, tc.peerIPv6(t, tc.peer1.ID).IsValid(), "peer1 should get an IPv6 address")
	drainPeerUpdates(tc.updMsg1)
	drainPeerUpdates(tc.updMsg2)
	drainPeerUpdates(tc.updMsg3)

	require.NoError(t, tc.manager.DeleteGroup(ctx, tc.accountID, userID, ipv6GroupD))
	require.False(t, tc.peerIPv6(t, tc.peer1.ID).IsValid(), "peer1 should lose its IPv6 address")

	peerShouldReceiveUpdate(t, tc.updMsg1)
	peerShouldReceiveUpdate(t, tc.updMsg2)
	peerShouldNotReceiveUpdate(t, tc.updMsg3)
}
