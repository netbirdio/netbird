package store

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	nbpeer "github.com/netbirdio/netbird/management/server/peer"
	"github.com/netbirdio/netbird/management/server/types"
)

const activityAccountID = "activityAccountId"

func newActivityTestStore(t *testing.T) Store {
	t.Helper()

	store, cleanUp, err := NewTestStoreFromSQL(context.Background(), "", t.TempDir())
	require.NoError(t, err)
	t.Cleanup(cleanUp)

	require.NoError(t, store.SaveAccount(context.Background(), &types.Account{
		Id:        activityAccountID,
		Domain:    "activity.example.com",
		CreatedAt: time.Now().UTC(),
	}))

	return store
}

func TestRefreshPeerLastSeen(t *testing.T) {
	ctx := context.Background()
	store := newActivityTestStore(t)
	stored := time.Now().UTC().Add(-3 * time.Hour)
	require.NoError(t, store.AddPeerToAccount(ctx, activityPeer(stored)))

	refreshed, err := store.RefreshPeerLastSeen(ctx, activityAccountID, "activityPeer", time.Now().UTC().Add(-time.Hour))
	require.NoError(t, err)
	assert.True(t, refreshed, "a peer seen three hours ago is stale enough to refresh")

	peer, err := store.GetPeerByID(ctx, LockingStrengthNone, activityAccountID, "activityPeer")
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().UTC(), peer.Status.LastSeen.UTC(), time.Minute, "last seen should be stamped at write time")
	assert.True(t, peer.Status.LastSeen.After(stored), "last seen must move forward")
}

// TestRefreshPeerLastSeenHonoursCutoff covers the throttle the caller relies on:
// two concurrent requests both read the same stale peer, but only the statement
// that still finds LastSeen behind the cutoff writes.
func TestRefreshPeerLastSeenHonoursCutoff(t *testing.T) {
	ctx := context.Background()
	store := newActivityTestStore(t)
	stored := time.Now().UTC().Add(-10 * time.Minute)
	require.NoError(t, store.AddPeerToAccount(ctx, activityPeer(stored)))

	refreshed, err := store.RefreshPeerLastSeen(ctx, activityAccountID, "activityPeer", time.Now().UTC().Add(-time.Hour))
	require.NoError(t, err)
	assert.False(t, refreshed, "a peer seen inside the interval must not be written")

	peer, err := store.GetPeerByID(ctx, LockingStrengthNone, activityAccountID, "activityPeer")
	require.NoError(t, err)
	assert.WithinDuration(t, stored, peer.Status.LastSeen.UTC(), time.Second, "last seen must be left where it was")
}

// TestRefreshPeerLastSeenRecordsNeverSeenPeer covers the nullable column. Status
// is an embedded pointer, so a peer stored without one leaves last seen NULL,
// and NULL loses the cutoff comparison — such a peer would never record its
// first activity.
func TestRefreshPeerLastSeenRecordsNeverSeenPeer(t *testing.T) {
	ctx := context.Background()
	store := newActivityTestStore(t)
	stored := activityPeer(time.Time{})
	stored.Status = nil
	require.NoError(t, store.AddPeerToAccount(ctx, stored))

	refreshed, err := store.RefreshPeerLastSeen(ctx, activityAccountID, "activityPeer", time.Now().UTC().Add(-time.Hour))
	require.NoError(t, err)
	assert.True(t, refreshed, "a peer that was never seen must record its first activity")

	peer, err := store.GetPeerByID(ctx, LockingStrengthNone, activityAccountID, "activityPeer")
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().UTC(), peer.Status.LastSeen.UTC(), time.Minute, "last seen should be stamped at write time")
}

// TestRefreshPeerLastSeenLeavesSessionStateAlone pins the column boundary: the
// connected flag and the session token belong to the sync stream that owns the
// peer's session, and a blind write here would corrupt its fencing. This is why
// SavePeerStatus is not reused for an activity bump.
func TestRefreshPeerLastSeenLeavesSessionStateAlone(t *testing.T) {
	ctx := context.Background()
	store := newActivityTestStore(t)

	stored := activityPeer(time.Date(2026, 3, 1, 9, 0, 0, 0, time.UTC))
	stored.Status.Connected = true
	stored.Status.SessionStartedAt = 1234567890
	require.NoError(t, store.AddPeerToAccount(ctx, stored))

	refreshed, err := store.RefreshPeerLastSeen(ctx, activityAccountID, "activityPeer", time.Now().UTC().Add(-time.Hour))
	require.NoError(t, err)
	require.True(t, refreshed, "the peer is stale enough to refresh")

	peer, err := store.GetPeerByID(ctx, LockingStrengthNone, activityAccountID, "activityPeer")
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().UTC(), peer.Status.LastSeen.UTC(), time.Minute, "last seen should move forward")
	assert.True(t, peer.Status.Connected, "connected flag must survive an activity write")
	assert.Equal(t, int64(1234567890), peer.Status.SessionStartedAt, "session token must survive an activity write")
}

func activityPeer(lastSeen time.Time) *nbpeer.Peer {
	return &nbpeer.Peer{
		ID:        "activityPeer",
		AccountID: activityAccountID,
		Key:       "activityPeerKey",
		IP:        netip.MustParseAddr("100.64.0.9"),
		Name:      "activity-peer",
		DNSLabel:  "activity-peer",
		Status:    &nbpeer.PeerStatus{LastSeen: lastSeen},
	}
}
