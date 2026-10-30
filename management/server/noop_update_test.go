package server

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/server/activity"
	resourceTypes "github.com/netbirdio/netbird/management/server/networks/resources/types"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

// countEvents returns how many stored events of the given activity target targetID.
// It must run after settleAffectedUpdates so asynchronous event writes have finished.
func countEvents(t *testing.T, manager *DefaultAccountManager, accountID, targetID string, codes ...activity.Activity) int {
	t.Helper()
	events, err := manager.eventStore.Get(context.Background(), accountID, 0, 10000, true)
	require.NoError(t, err)
	n := 0
	for _, e := range events {
		if e.TargetID != targetID {
			continue
		}
		for _, code := range codes {
			if e.Activity == code {
				n++
			}
		}
	}
	return n
}

// assertNoPeerUpdate advances the synctest clock past every update buffer interval
// and asserts that none of the channels received an update.
func assertNoPeerUpdate(t *testing.T, msg string, chans ...<-chan *network_map.UpdateMessage) {
	t.Helper()
	time.Sleep(peerUpdateSettleTime)
	synctest.Wait()
	for _, ch := range chans {
		assert.Zero(t, len(ch), msg)
	}
}

func TestSavePolicy_UnchangedSkipsWritesAndUpdates(t *testing.T) {
	t.Setenv("NB_EVENT_ACTIVITY_LOG_ENABLED", "true")
	runPeerUpdateTest(t, func(t *testing.T) {
		ctx := context.Background()
		manager, updateManager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)

		require.NoError(t, manager.CreateGroup(ctx, account.Id, userID, &types.Group{ID: "noopA", Name: "noopA", Peers: []string{peer1.ID, peer2.ID}}))
		require.NoError(t, manager.CreateGroup(ctx, account.Id, userID, &types.Group{ID: "noopB", Name: "noopB", Peers: []string{peer3.ID}}))

		created, err := manager.SavePolicy(ctx, account.Id, userID, &types.Policy{
			AccountID: account.Id,
			Name:      "noop-policy",
			Enabled:   true,
			Rules: []*types.PolicyRule{{
				Enabled:      true,
				Sources:      []string{"noopA", "noopB"},
				Destinations: []string{"noopB"},
				Protocol:     types.PolicyRuleProtocolTCP,
				Ports:        []string{"80", "443"},
				Action:       types.PolicyTrafficActionAccept,
			}},
		}, true)
		require.NoError(t, err)
		require.NotEmpty(t, created.PublicID)

		updMsg := updateManager.CreateChannel(ctx, peer1.ID)
		t.Cleanup(func() { updateManager.CloseChannel(ctx, peer1.ID) })
		settleAffectedUpdates(updMsg)

		ruleID := created.Rules[0].ID
		samePolicy := func(ports ...string) *types.Policy {
			return &types.Policy{
				ID:        created.ID,
				AccountID: account.Id,
				Name:      "noop-policy",
				Enabled:   true,
				Rules: []*types.PolicyRule{{
					ID:           ruleID,
					PolicyID:     created.ID,
					Enabled:      true,
					Sources:      []string{"noopB", "noopA"},
					Destinations: []string{"noopB"},
					Protocol:     types.PolicyRuleProtocolTCP,
					Ports:        ports,
					Action:       types.PolicyTrafficActionAccept,
				}},
			}
		}

		step(t, "unchanged update with permuted slices", func(t *testing.T) {
			serialBefore := networkSerial(t, manager, account.Id)
			eventsBefore := countEvents(t, manager, account.Id, created.ID, activity.PolicyUpdated)

			resp, err := manager.SavePolicy(ctx, account.Id, userID, samePolicy("443", "80"), false)
			require.NoError(t, err)
			assert.Equal(t, created.PublicID, resp.PublicID, "unchanged update should return the stored public ID")

			assertNoPeerUpdate(t, "unchanged policy update must not push a peer update", updMsg)
			assert.Equal(t, serialBefore, networkSerial(t, manager, account.Id), "unchanged policy update must not bump the network serial")
			assert.Equal(t, eventsBefore+1, countEvents(t, manager, account.Id, created.ID, activity.PolicyUpdated),
				"unchanged policy update should still record a PolicyUpdated event")
		})

		step(t, "changed update", func(t *testing.T) {
			serialBefore := networkSerial(t, manager, account.Id)
			eventsBefore := countEvents(t, manager, account.Id, created.ID, activity.PolicyUpdated)

			_, err := manager.SavePolicy(ctx, account.Id, userID, samePolicy("443", "8080"), false)
			require.NoError(t, err)

			peerShouldReceiveUpdate(t, updMsg)
			settleAffectedUpdates(updMsg)
			assert.Equal(t, serialBefore+1, networkSerial(t, manager, account.Id), "changed policy update must bump the network serial")
			assert.Equal(t, eventsBefore+1, countEvents(t, manager, account.Id, created.ID, activity.PolicyUpdated),
				"changed policy update should record a PolicyUpdated event")
		})
	})
}

func TestUpdateResource_UnchangedSkipsWritesAndUpdates(t *testing.T) {
	t.Setenv("NB_EVENT_ACTIVITY_LOG_ENABLED", "true")
	runPeerUpdateTest(t, func(t *testing.T) {
		ctx := context.Background()
		s := setupRouterScenario(t, true)

		const secondGroupID = "rs-noop-grp"
		require.NoError(t, s.manager.CreateGroup(ctx, s.accountID, userID, &types.Group{ID: secondGroupID, Name: "rs-noop"}))

		_, err := s.manager.SavePolicy(ctx, s.accountID, userID, peerToResourcePolicyByGroup(s.sourceGroupID, s.resourceGroupID), true)
		require.NoError(t, err)

		resourcesManager, _, _ := s.managers()

		resourceWith := func(address string, groupIDs ...string) *resourceTypes.NetworkResource {
			return &resourceTypes.NetworkResource{
				ID:        s.resourceID,
				AccountID: s.accountID,
				NetworkID: s.networkID,
				Name:      "rs-resource-host",
				Address:   address,
				GroupIDs:  groupIDs,
				Enabled:   true,
			}
		}

		_, err = resourcesManager.UpdateResource(ctx, userID, resourceWith("10.20.30.0/24", s.resourceGroupID, secondGroupID))
		require.NoError(t, err)

		stored, err := s.manager.Store.GetNetworkResourceByID(ctx, store.LockingStrengthNone, s.accountID, s.resourceID)
		require.NoError(t, err)

		sourceCh := s.updateManager.CreateChannel(ctx, s.sourcePeerID)
		t.Cleanup(func() { s.updateManager.CloseChannel(ctx, s.sourcePeerID) })
		routerCh := s.updateManager.CreateChannel(ctx, s.routerPeerID)
		t.Cleanup(func() { s.updateManager.CloseChannel(ctx, s.routerPeerID) })
		settleAffectedUpdates(sourceCh, routerCh)

		step(t, "unchanged update with permuted group IDs", func(t *testing.T) {
			serialBefore := networkSerial(t, s.manager, s.accountID)
			eventsBefore := countEvents(t, s.manager, s.accountID, s.resourceID, activity.NetworkResourceUpdated)

			resp, err := resourcesManager.UpdateResource(ctx, userID, resourceWith("10.20.30.0/24", secondGroupID, s.resourceGroupID))
			require.NoError(t, err)
			assert.Equal(t, stored.PublicID, resp.PublicID, "unchanged update should return the stored public ID")
			assert.Equal(t, resourceTypes.Subnet, resp.Type, "unchanged update should return the parsed resource type")

			assertNoPeerUpdate(t, "unchanged resource update must not push a peer update", sourceCh, routerCh)
			assert.Equal(t, serialBefore, networkSerial(t, s.manager, s.accountID), "unchanged resource update must not bump the network serial")
			assert.Equal(t, eventsBefore+1, countEvents(t, s.manager, s.accountID, s.resourceID, activity.NetworkResourceUpdated),
				"unchanged resource update should still record a NetworkResourceUpdated event")
		})

		step(t, "changed update", func(t *testing.T) {
			serialBefore := networkSerial(t, s.manager, s.accountID)
			eventsBefore := countEvents(t, s.manager, s.accountID, s.resourceID, activity.NetworkResourceUpdated)

			_, err := resourcesManager.UpdateResource(ctx, userID, resourceWith("10.20.31.0/24", secondGroupID, s.resourceGroupID))
			require.NoError(t, err)

			peerShouldReceiveUpdate(t, sourceCh)
			peerShouldReceiveUpdate(t, routerCh)
			settleAffectedUpdates(sourceCh, routerCh)
			assert.Equal(t, serialBefore+1, networkSerial(t, s.manager, s.accountID), "changed resource update must bump the network serial")
			assert.Equal(t, eventsBefore+1, countEvents(t, s.manager, s.accountID, s.resourceID, activity.NetworkResourceUpdated),
				"changed resource update should record a NetworkResourceUpdated event")
		})
	})
}

func TestUpdateGroup_UnchangedSkipsWritesAndUpdates(t *testing.T) {
	t.Setenv("NB_EVENT_ACTIVITY_LOG_ENABLED", "true")
	runPeerUpdateTest(t, func(t *testing.T) {
		ctx := context.Background()
		manager, updateManager, account, peer1, peer2, _ := setupNetworkMapTest(t)

		const groupID = "noop-group"
		resources := []types.Resource{
			{ID: "noop-res-1", Type: types.ResourceTypeHost},
			{ID: "noop-res-2", Type: types.ResourceTypeSubnet},
		}
		require.NoError(t, manager.CreateGroup(ctx, account.Id, userID, &types.Group{
			ID: groupID, Name: "noop-group", Issued: types.GroupIssuedAPI, Peers: []string{peer1.ID, peer2.ID}, Resources: resources,
		}))
		_, err := manager.SavePolicy(ctx, account.Id, userID, &types.Policy{
			AccountID: account.Id,
			Name:      "noop-group-policy",
			Enabled:   true,
			Rules: []*types.PolicyRule{{
				Enabled:       true,
				Sources:       []string{groupID},
				Destinations:  []string{groupID},
				Bidirectional: true,
				Action:        types.PolicyTrafficActionAccept,
			}},
		}, true)
		require.NoError(t, err)

		stored, err := manager.Store.GetGroupByID(ctx, store.LockingStrengthNone, account.Id, groupID)
		require.NoError(t, err)

		updMsg := updateManager.CreateChannel(ctx, peer1.ID)
		t.Cleanup(func() { updateManager.CloseChannel(ctx, peer1.ID) })
		settleAffectedUpdates(updMsg)

		groupEvents := []activity.Activity{activity.GroupUpdated, activity.GroupAddedToPeer, activity.GroupRemovedFromPeer}
		countGroupEvents := func() int {
			n := countEvents(t, manager, account.Id, groupID, groupEvents...)
			for _, peerID := range []string{peer1.ID, peer2.ID} {
				n += countEvents(t, manager, account.Id, peerID, groupEvents...)
			}
			return n
		}
		permuted := func(peers ...string) *types.Group {
			return &types.Group{
				ID:        groupID,
				Name:      "noop-group",
				Issued:    types.GroupIssuedAPI,
				Peers:     peers,
				Resources: []types.Resource{resources[1], resources[0]},
			}
		}

		step(t, "unchanged update with permuted peers and resources", func(t *testing.T) {
			serialBefore := networkSerial(t, manager, account.Id)
			eventsBefore := countGroupEvents()

			g := permuted(peer2.ID, peer1.ID)
			require.NoError(t, manager.UpdateGroup(ctx, account.Id, userID, g))
			assert.Equal(t, stored.PublicID, g.PublicID, "unchanged update should carry the stored public ID")

			assertNoPeerUpdate(t, "unchanged group update must not push a peer update", updMsg)
			assert.Equal(t, serialBefore, networkSerial(t, manager, account.Id), "unchanged group update must not bump the network serial")
			assert.Equal(t, eventsBefore, countGroupEvents(), "unchanged group update should record no group events")
		})

		step(t, "unchanged bulk update", func(t *testing.T) {
			serialBefore := networkSerial(t, manager, account.Id)
			eventsBefore := countGroupEvents()

			require.NoError(t, manager.UpdateGroups(ctx, account.Id, userID, []*types.Group{permuted(peer2.ID, peer1.ID)}))

			assertNoPeerUpdate(t, "unchanged bulk group update must not push a peer update", updMsg)
			assert.Equal(t, serialBefore, networkSerial(t, manager, account.Id), "unchanged bulk group update must not bump the network serial")
			assert.Equal(t, eventsBefore, countGroupEvents(), "unchanged bulk group update should record no group events")
		})

		step(t, "changed update", func(t *testing.T) {
			serialBefore := networkSerial(t, manager, account.Id)

			require.NoError(t, manager.UpdateGroup(ctx, account.Id, userID, permuted(peer1.ID)))

			peerShouldReceiveUpdate(t, updMsg)
			settleAffectedUpdates(updMsg)
			assert.Equal(t, serialBefore+1, networkSerial(t, manager, account.Id), "changed group update must bump the network serial")
			assert.Equal(t, 1, countEvents(t, manager, account.Id, peer2.ID, activity.GroupRemovedFromPeer),
				"removing a peer should record a GroupRemovedFromPeer event")
		})

		step(t, "changed bulk update", func(t *testing.T) {
			serialBefore := networkSerial(t, manager, account.Id)

			renamed := permuted(peer1.ID)
			renamed.Name = "noop-group-renamed"
			require.NoError(t, manager.UpdateGroups(ctx, account.Id, userID, []*types.Group{renamed}))

			peerShouldReceiveUpdate(t, updMsg)
			settleAffectedUpdates(updMsg)
			assert.Equal(t, serialBefore+1, networkSerial(t, manager, account.Id), "changed bulk group update must bump the network serial")
			assert.Equal(t, 1, countEvents(t, manager, account.Id, groupID, activity.GroupUpdated),
				"renaming a group should record a GroupUpdated event")
		})
	})
}
