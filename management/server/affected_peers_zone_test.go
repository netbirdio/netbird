package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/internals/controllers/network_map"
	"github.com/netbirdio/netbird/management/internals/modules/zones"
	"github.com/netbirdio/netbird/management/internals/modules/zones/records"
	"github.com/netbirdio/netbird/management/server/affectedpeers"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
)

const affectedZoneDomain = "zone.test"

// createAffectedZone stores a zone distributed to the given groups, optionally with
// one A record so the network map actually ships it.
func createAffectedZone(t *testing.T, s store.Store, accountID, domain string, enabled, withRecord bool, groups []string) *zones.Zone {
	t.Helper()
	ctx := context.Background()

	zone := zones.NewZone(accountID, domain, domain, enabled, false, groups)
	require.NoError(t, s.CreateZone(ctx, zone))

	if withRecord {
		record := records.NewRecord(accountID, zone.ID, "host."+domain, records.RecordTypeA, "10.0.0.1", 300)
		require.NoError(t, s.CreateDNSRecord(ctx, record))
	}

	return zone
}

func TestCollectGroupChange_ZoneLinked(t *testing.T) {
	_, s, accountID, _, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	createAffectedZone(t, s, accountID, affectedZoneDomain, true, true, []string{groupIDs[0]})

	groups, _ := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0]})
	assert.Contains(t, groups, groupIDs[0], "group distributed a zone should be affected by its own change")

	groups, _ = collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[1]})
	assert.Empty(t, groups, "group not referenced by any zone should not be affected")
}

func TestCollectGroupChange_UnshippedZoneNotLinked(t *testing.T) {
	_, s, accountID, _, groupIDs := setupAffectedPeersTest(t)
	ctx := context.Background()

	// Disabled zone and zone without records are never shipped by the network map.
	createAffectedZone(t, s, accountID, "disabled."+affectedZoneDomain, false, true, []string{groupIDs[0]})
	createAffectedZone(t, s, accountID, "empty."+affectedZoneDomain, true, false, []string{groupIDs[1]})

	groups, _ := collectGroupChangeAffectedGroups(ctx, s, accountID, []string{groupIDs[0], groupIDs[1]})
	assert.Empty(t, groups, "groups referenced only by unshipped zones should not be affected")
}

func TestResolveAffectedPeers_ZoneGroupMembershipChange(t *testing.T) {
	_, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)

	createAffectedZone(t, s, accountID, affectedZoneDomain, true, true, []string{groupIDs[0]})

	// Same change shape UpdateGroup builds: the group changed as a whole and peer1
	// left it, so peer1 must refresh to drop the zone.
	change := affectedpeers.Change{
		ChangedGroupIDs:     []string{groupIDs[0]},
		RemovedPeersByGroup: map[string][]string{groupIDs[0]: {peerIDs[1]}},
	}

	result := resolveAffected(t, s, accountID, change)
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[1]}, result, "current and removed members of the zone group should be affected")
}

func TestResolveAffectedPeers_ZoneDistributionChange(t *testing.T) {
	_, s, accountID, peerIDs, groupIDs := setupAffectedPeersTest(t)

	// Zone create/update/delete passes old and new distribution groups.
	change := affectedpeers.Change{DistributionGroupIDs: []string{groupIDs[0], groupIDs[2]}}

	result := resolveAffected(t, s, accountID, change)
	assert.ElementsMatch(t, []string{peerIDs[0], peerIDs[2]}, result, "only members of the distribution groups should be affected")
}

// TestAffectedPeers_ZoneGroupUpdate_NewMemberReceivesZone verifies that adding a peer
// to a group referenced only by a zone pushes the zone to the new member and leaves
// unrelated peers alone.
func TestAffectedPeers_ZoneGroupUpdate_NewMemberReceivesZone(t *testing.T) {
	manager, updateManager, account, peer1, peer2, peer3 := setupNetworkMapTest(t)
	ctx := context.Background()
	accountID := account.Id

	policies, err := manager.Store.GetAccountPolicies(ctx, store.LockingStrengthNone, accountID)
	require.NoError(t, err)
	for _, p := range policies {
		require.NoError(t, manager.Store.DeletePolicy(ctx, accountID, p.ID))
	}

	zoneGroup := &types.Group{ID: "zone-grp", Name: "ZoneGroup", Peers: []string{peer1.ID}}
	require.NoError(t, manager.CreateGroup(ctx, accountID, userID, zoneGroup))

	createAffectedZone(t, manager.Store, accountID, affectedZoneDomain, true, true, []string{zoneGroup.ID})

	updMsg1 := updateManager.CreateChannel(ctx, peer1.ID)
	updMsg2 := updateManager.CreateChannel(ctx, peer2.ID)
	updMsg3 := updateManager.CreateChannel(ctx, peer3.ID)
	t.Cleanup(func() {
		updateManager.CloseChannel(ctx, peer1.ID)
		updateManager.CloseChannel(ctx, peer2.ID)
		updateManager.CloseChannel(ctx, peer3.ID)
	})

	zoneGroup.Peers = []string{peer1.ID, peer2.ID}
	require.NoError(t, manager.UpdateGroup(ctx, accountID, userID, zoneGroup))

	peerShouldReceiveUpdate(t, updMsg1)
	msg := receivePeerUpdate(t, updMsg2)
	assert.True(t, syncHasCustomZone(msg, affectedZoneDomain+"."), "new zone group member should receive the zone")
	peerShouldNotReceiveUpdate(t, updMsg3)
}

func receivePeerUpdate(t *testing.T, ch <-chan *network_map.UpdateMessage) *network_map.UpdateMessage {
	t.Helper()
	select {
	case msg := <-ch:
		require.NotNil(t, msg, "update message should not be nil")
		return msg
	case <-time.After(peerUpdateTimeout):
		require.FailNow(t, "timed out waiting for update message")
		return nil
	}
}

func syncHasCustomZone(msg *network_map.UpdateMessage, domain string) bool {
	for _, zone := range msg.Update.GetNetworkMap().GetDNSConfig().GetCustomZones() {
		if zone.GetDomain() == domain {
			return true
		}
	}
	return false
}
