package server

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/netbirdio/netbird/management/server/activity"
	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/store"
	"github.com/netbirdio/netbird/management/server/types"
	"github.com/netbirdio/netbird/shared/management/status"
)

type batchGroupFixture struct {
	manager   *DefaultAccountManager
	accountID string
	groupID   string
	peers     []string
}

// newBatchGroupFixture creates an account with three peers and an API group holding the first one.
func newBatchGroupFixture(t *testing.T) *batchGroupFixture {
	t.Helper()

	manager, _, account, peer1, peer2, peer3 := setupNetworkMapTest(t)
	group := &types.Group{ID: "batch-group", Name: "batch", Issued: types.GroupIssuedAPI, Peers: []string{peer1.ID}}
	require.NoError(t, manager.CreateGroup(context.Background(), account.Id, userID, group))

	return &batchGroupFixture{
		manager:   manager,
		accountID: account.Id,
		groupID:   group.ID,
		peers:     []string{peer1.ID, peer2.ID, peer3.ID},
	}
}

func (f *batchGroupFixture) members(t *testing.T, groupID string) []string {
	t.Helper()
	group, err := f.manager.Store.GetGroupByID(context.Background(), store.LockingStrengthNone, f.accountID, groupID)
	require.NoError(t, err)
	return group.Peers
}

func (f *batchGroupFixture) serial(t *testing.T) uint64 {
	t.Helper()
	network, err := f.manager.Store.GetAccountNetwork(context.Background(), store.LockingStrengthNone, f.accountID)
	require.NoError(t, err)
	return network.Serial
}

func assertStatusType(t *testing.T, err error, want status.Type) {
	t.Helper()
	require.Error(t, err)
	s, ok := status.FromError(err)
	require.True(t, ok, "expected status error, got %v", err)
	assert.Equal(t, want, s.Type())
}

func TestDefaultAccountManager_GroupPeersBatch_PermissionDenied(t *testing.T) {
	f := newBatchGroupFixture(t)

	const regularUser = "regular-user"
	require.NoError(t, f.manager.Store.SaveUser(context.Background(), &types.User{
		Id:        regularUser,
		AccountID: f.accountID,
		Role:      types.UserRoleUser,
	}))

	_, err := f.manager.AddPeersToGroup(context.Background(), f.accountID, regularUser, f.groupID, f.peers[1:])
	assertStatusType(t, err, status.PermissionDenied)

	_, err = f.manager.RemovePeersFromGroup(context.Background(), f.accountID, regularUser, f.groupID, f.peers[:1])
	assertStatusType(t, err, status.PermissionDenied)

	assert.ElementsMatch(t, f.peers[:1], f.members(t, f.groupID), "denied requests must not change membership")
}

func TestDefaultAccountManager_GroupPeersBatch_RejectsAllGroup(t *testing.T) {
	f := newBatchGroupFixture(t)

	all, err := f.manager.Store.GetGroupByName(context.Background(), store.LockingStrengthNone, f.accountID, types.GroupAllName)
	require.NoError(t, err)
	before := f.members(t, all.ID)
	serial := f.serial(t)

	_, err = f.manager.AddPeersToGroup(context.Background(), f.accountID, userID, all.ID, f.peers[:1])
	assertStatusType(t, err, status.InvalidArgument)

	_, err = f.manager.RemovePeersFromGroup(context.Background(), f.accountID, userID, all.ID, f.peers[:1])
	assertStatusType(t, err, status.InvalidArgument)

	assert.ElementsMatch(t, before, f.members(t, all.ID))
	assert.Equal(t, serial, f.serial(t), "rejected requests must not bump the network serial")
}

func TestDefaultAccountManager_GroupPeersBatch_EmptyAndUnknownGroup(t *testing.T) {
	f := newBatchGroupFixture(t)

	_, err := f.manager.AddPeersToGroup(context.Background(), f.accountID, userID, f.groupID, nil)
	assertStatusType(t, err, status.InvalidArgument)

	_, err = f.manager.RemovePeersFromGroup(context.Background(), f.accountID, userID, f.groupID, []string{})
	assertStatusType(t, err, status.InvalidArgument)

	_, err = f.manager.AddPeersToGroup(context.Background(), f.accountID, userID, "missing-group", f.peers[1:])
	assertStatusType(t, err, status.NotFound)
}

func TestDefaultAccountManager_GroupPeersBatch_UnknownIDRejectsAtomically(t *testing.T) {
	f := newBatchGroupFixture(t)
	serial := f.serial(t)

	_, err := f.manager.AddPeersToGroup(context.Background(), f.accountID, userID, f.groupID, []string{f.peers[1], "does-not-exist", f.peers[2]})
	assertStatusType(t, err, status.InvalidArgument)
	assert.ElementsMatch(t, f.peers[:1], f.members(t, f.groupID), "no peer may be added when one ID is unknown")

	// The unknown ID rejects the request even though the known ID is a current member.
	_, err = f.manager.RemovePeersFromGroup(context.Background(), f.accountID, userID, f.groupID, []string{f.peers[0], "does-not-exist"})
	assertStatusType(t, err, status.InvalidArgument)
	assert.ElementsMatch(t, f.peers[:1], f.members(t, f.groupID), "no peer may be removed when one ID is unknown")

	assert.Equal(t, serial, f.serial(t), "rejected requests must not bump the network serial")
}

func TestDefaultAccountManager_GroupPeersBatch_RejectsForeignPeer(t *testing.T) {
	f := newBatchGroupFixture(t)

	otherAccount, err := createAccount(f.manager, "other_account", "other_user", "")
	require.NoError(t, err)
	foreign := &nbpeer.Peer{
		ID:        "foreign-peer",
		AccountID: otherAccount.Id,
		Key:       "foreign-key",
		DNSLabel:  "foreign-peer",
		IP:        uint32ToIP(1),
	}
	require.NoError(t, f.manager.Store.AddPeerToAccount(context.Background(), foreign))

	_, err = f.manager.AddPeersToGroup(context.Background(), f.accountID, userID, f.groupID, []string{f.peers[1], foreign.ID})
	assertStatusType(t, err, status.InvalidArgument)
	assert.ElementsMatch(t, f.peers[:1], f.members(t, f.groupID))
}

func TestDefaultAccountManager_GroupPeersBatch_AddAndRemove(t *testing.T) {
	f := newBatchGroupFixture(t)

	group, err := f.manager.AddPeersToGroup(context.Background(), f.accountID, userID, f.groupID, []string{f.peers[1], f.peers[2], f.peers[1]})
	require.NoError(t, err)
	assert.ElementsMatch(t, f.peers, group.Peers, "duplicate IDs are added once and the returned group is current")
	assert.ElementsMatch(t, f.peers, f.members(t, f.groupID))

	group, err = f.manager.RemovePeersFromGroup(context.Background(), f.accountID, userID, f.groupID, []string{f.peers[0], f.peers[2]})
	require.NoError(t, err)
	assert.ElementsMatch(t, f.peers[1:2], group.Peers)
	assert.ElementsMatch(t, f.peers[1:2], f.members(t, f.groupID))

	// IDs that exist in the account but are not members are skipped.
	group, err = f.manager.RemovePeersFromGroup(context.Background(), f.accountID, userID, f.groupID, []string{f.peers[0], f.peers[1]})
	require.NoError(t, err)
	assert.Empty(t, group.Peers)
}

func TestDefaultAccountManager_GroupPeersBatch_IntegrationGroupAllowed(t *testing.T) {
	f := newBatchGroupFixture(t)

	integration := &types.Group{ID: "integration-group", Name: "idp-devs", Issued: types.GroupIssuedIntegration}
	require.NoError(t, f.manager.CreateGroup(context.Background(), f.accountID, userID, integration))

	group, err := f.manager.AddPeersToGroup(context.Background(), f.accountID, userID, integration.ID, f.peers[:2])
	require.NoError(t, err)
	assert.ElementsMatch(t, f.peers[:2], group.Peers)
}

func TestDefaultAccountManager_GroupPeersBatch_NoOpKeepsSerial(t *testing.T) {
	f := newBatchGroupFixture(t)
	serial := f.serial(t)

	group, err := f.manager.AddPeersToGroup(context.Background(), f.accountID, userID, f.groupID, f.peers[:1])
	require.NoError(t, err)
	assert.ElementsMatch(t, f.peers[:1], group.Peers, "no-op add returns the current group")
	assert.Equal(t, serial, f.serial(t), "adding existing members must not bump the serial")

	group, err = f.manager.RemovePeersFromGroup(context.Background(), f.accountID, userID, f.groupID, f.peers[1:])
	require.NoError(t, err)
	assert.ElementsMatch(t, f.peers[:1], group.Peers, "no-op remove returns the current group")
	assert.Equal(t, serial, f.serial(t), "removing non-members must not bump the serial")
}

func TestDefaultAccountManager_GroupPeersBatch_BumpsSerialOnce(t *testing.T) {
	f := newBatchGroupFixture(t)

	serial := f.serial(t)
	_, err := f.manager.AddPeersToGroup(context.Background(), f.accountID, userID, f.groupID, f.peers[1:])
	require.NoError(t, err)
	assert.Equal(t, serial+1, f.serial(t), "one add request must bump the serial exactly once")

	serial = f.serial(t)
	_, err = f.manager.RemovePeersFromGroup(context.Background(), f.accountID, userID, f.groupID, f.peers)
	require.NoError(t, err)
	assert.Equal(t, serial+1, f.serial(t), "one remove request must bump the serial exactly once")
}

func TestDefaultAccountManager_GroupPeersBatch_StoresEventPerPeer(t *testing.T) {
	t.Setenv("NB_EVENT_ACTIVITY_LOG_ENABLED", "true")
	f := newBatchGroupFixture(t)

	// eventTargets returns false on a store error so a polling caller retries without running
	// require in the poll goroutine.
	eventTargets := func(code activity.Activity) (map[string]bool, bool) {
		events, err := f.manager.eventStore.Get(context.Background(), f.accountID, 0, 100, true)
		if err != nil {
			return nil, false
		}
		targets := make(map[string]bool)
		for _, event := range events {
			if event.Activity == code {
				targets[event.TargetID] = true
			}
		}
		return targets, true
	}

	_, err := f.manager.AddPeersToGroup(context.Background(), f.accountID, userID, f.groupID, f.peers[1:])
	require.NoError(t, err)
	assert.Eventually(t, func() bool {
		targets, ok := eventTargets(activity.GroupAddedToPeer)
		return ok && targets[f.peers[1]] && targets[f.peers[2]]
	}, time.Second, 10*time.Millisecond, "each added peer should get a GroupAddedToPeer event")

	_, err = f.manager.RemovePeersFromGroup(context.Background(), f.accountID, userID, f.groupID, f.peers[1:])
	require.NoError(t, err)
	assert.Eventually(t, func() bool {
		targets, ok := eventTargets(activity.GroupRemovedFromPeer)
		return ok && targets[f.peers[1]] && targets[f.peers[2]]
	}, time.Second, 10*time.Millisecond, "each removed peer should get a GroupRemovedFromPeer event")
}
